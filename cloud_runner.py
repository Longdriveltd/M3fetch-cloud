"""GitHub Actions 云端执行器: 从 CF KV 领任务 -> vfetch 下载 -> 传 R2 -> 回写链接.

所有凭证从环境变量读 (GitHub Secrets), 不落盘、不回显:
  API_BASE      Worker API 根, 如 https://uniqcard.us.ci/api
  AGENT_TOKEN   与 Worker secret 同名 (claim/finish/progress 鉴权)
  R2_ACCOUNT_ID Cloudflare Account ID
  R2_ACCESS_KEY R2 API Token 的 Access Key ID
  R2_SECRET_KEY R2 API Token 的 Secret Access Key
  R2_BUCKET     R2 bucket 名 (如 m3fetch)
  R2_PUBLIC_BASE bucket 的公开访问域名(尾不带 /), 如 https://pub-xxx.r2.dev
                 或自定义域 https://files.yourdomain.com

流程与本机 agent.py 完全兼容: 复用同一套 /api/claim /api/progress /api/finish.
产物落到临时目录, 上传 R2 用 <id>/<安全文件名> 作 key, finish 时 path = 公开直链.
"""
import os
import re
import sys
import time
import json
import subprocess
import urllib.parse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
VFETCH = os.path.join(HERE, 'vfetch.py')
PY = sys.executable


def env(name, required=True):
    v = os.environ.get(name, '').strip()
    if required and not v:
        raise RuntimeError('缺少环境变量 ' + name)
    return v


API_BASE = None
HDR = None


def api(method, path, body=None, timeout=30):
    r = requests.request(method, API_BASE + path, headers=HDR,
                         json=body, timeout=timeout)
    try:
        return r.json()
    except ValueError:
        raise RuntimeError('API 非 JSON: HTTP %d %s' % (r.status_code, r.text[:200]))


def safe_name(name, fallback='media'):
    """R2 key 用文件名: 去路径/危险字符, 保留中英文与常见符号."""
    name = str(name or '').strip().replace('\\', '/').split('/')[-1]
    name = re.sub(r'[<>:"|?*\x00-\x1f]', '', name).strip(' .')
    return (name or fallback)[:120]


def r2_upload(local_path, key):
    """用 boto3 (S3 兼容) 上传到 R2. 依赖已在 workflow 安装."""
    import boto3
    from botocore.config import Config
    acct = env('R2_ACCOUNT_ID')
    s3 = boto3.client(
        's3',
        endpoint_url='https://%s.r2.cloudflarestorage.com' % acct,
        aws_access_key_id=env('R2_ACCESS_KEY'),
        aws_secret_access_key=env('R2_SECRET_KEY'),
        region_name='auto',
        config=Config(signature_version='s3v4'),
    )
    public_type = 'public-read'  # bucket 需开启公开访问; 若用自定义域则此 ACL 无害
    with open(local_path, 'rb') as f:
        try:
            s3.put_object(Bucket=env('R2_BUCKET'), Key=key, Body=f,
                          ContentType=guess_ct(local_path), ACL=public_type)
        except Exception:
            # 某些 R2 配置禁用 ACL, 去掉重试一次
            f.seek(0)
            s3.put_object(Bucket=env('R2_BUCKET'), Key=key, Body=f,
                          ContentType=guess_ct(local_path))


def guess_ct(path):
    ext = os.path.splitext(path)[1].lower()
    return {
        '.mp4': 'video/mp4', '.mkv': 'video/x-matroska', '.ts': 'video/mp2t',
        '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp',
        '.gif': 'image/gif', '.bmp': 'image/bmp',
    }.get(ext, 'application/octet-stream')


def run_vfetch(task, outdir):
    cmd = [PY, VFETCH, task['url'], '-f', task.get('fmt') or 'mp4',
           '-o', outdir, '--overwrite']
    custom = str(task.get('name') or '').strip()
    if custom:
        cmd += ['--name', custom]
    else:
        cmd += ['--auto-name', 'cloud_' + str(task['id'])]
    ep = (task.get('ep') or '').strip()
    if ep:
        cmd += ['--episode', ep]
    print('  执行 vfetch: %s' % ' '.join(
        x if not x.startswith('http') else '<url>' for x in cmd[1:]), flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=12000)
    if r.returncode != 0:
        raise RuntimeError('vfetch rc=%d; %s' % (r.returncode, (r.stderr or r.stdout or '')[-400:]))
    # 产物: 优先 vfetch 自己打印的 [OK  ] 行
    for ln in (r.stdout or '').splitlines():
        if ln.startswith('[OK  ] '):
            p = ln[7:].rsplit(' (', 1)[0].strip()
            if p and os.path.isfile(p):
                return p
    # 回退: 目录里最新文件
    exts = ('.mp4', '.mkv', '.ts', '.mp3', '.m4a',
            '.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp')
    files = [os.path.join(outdir, f) for f in os.listdir(outdir)
             if os.path.splitext(f)[1].lower() in exts]
    if not files:
        raise RuntimeError('未找到落盘产物')
    return max(files, key=os.path.getmtime)


def process(task):
    tid = task['id']
    t0 = time.time()
    outdir = os.path.join(HERE, '_tmp', tid)
    os.makedirs(outdir, exist_ok=True)
    try:
        print('领取任务 %s: %s [%s]' % (tid, task['url'], task.get('fmt')), flush=True)
        try:
            api('POST', '/progress', {'id': tid, 'phase': '云端解析中…'})
        except Exception:
            pass
        local = run_vfetch(task, outdir)
        size = os.path.getsize(local)
        base = safe_name(task.get('name') or os.path.basename(local), tid)
        ext = os.path.splitext(local)[1]
        fname = base if base.lower().endswith(ext) else base + ext
        key = '%s/%s' % (tid, fname)
        print('  上传 R2: %s (%.1f MB)' % (key, size / 1048576.0), flush=True)
        r2_upload(local, key)
        public = env('R2_PUBLIC_BASE').rstrip('/') + '/' + urllib.parse.quote(key)
        api('POST', '/finish', {'id': tid, 'ok': True, 'path': public,
                                'size': size, 'secs': round(time.time() - t0, 1)})
        print('  完成 -> %s' % public, flush=True)
    except Exception as e:
        print('  任务 %s 失败: %s' % (tid, e), flush=True)
        try:
            api('POST', '/finish', {'id': tid, 'ok': False, 'err': str(e)[:500]})
        except Exception as e2:
            print('  回写失败状态也失败: %s' % e2, flush=True)
    finally:
        # 清理临时产物 (R2 已有副本)
        try:
            import shutil
            shutil.rmtree(outdir, ignore_errors=True)
        except Exception:
            pass


def main():
    global API_BASE, HDR
    API_BASE = env('API_BASE').rstrip('/')
    HDR = {'X-Agent-Token': env('AGENT_TOKEN')}
    # 验证凭证齐全 (R2 在真有任务时才用到, 但先检查避免空跑)
    for k in ('R2_ACCOUNT_ID', 'R2_ACCESS_KEY', 'R2_SECRET_KEY', 'R2_BUCKET', 'R2_PUBLIC_BASE'):
        env(k)
    max_jobs = int(os.environ.get('MAX_JOBS', '20'))
    n = 0
    print('云端执行器启动: 最多处理 %d 个任务' % max_jobs, flush=True)
    while n < max_jobs:
        try:
            d = api('GET', '/claim', timeout=30)
        except Exception as e:
            print('claim 失败: %s; 30s 后重试' % e, flush=True)
            time.sleep(30)
            continue
        if not d.get('ok') or not d.get('task'):
            print('队列已空, 退出', flush=True)
            break
        process(d['task'])
        n += 1
    print('本次共处理 %d 个任务' % n, flush=True)


if __name__ == '__main__':
    main()
