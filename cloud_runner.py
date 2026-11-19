"""GitHub Actions 云端执行器: 从 CF KV 领任务 -> vfetch 下载 -> 传 GitHub Releases -> 回写下载链接.

所有凭证从环境变量读 (GitHub Secrets + Actions 自动注入), 不落盘、不回显:
  API_BASE           Worker API 根, 如 https://uniqcard.us.ci/api
  AGENT_TOKEN        与 Worker secret 同名 (claim/finish/progress 鉴权)
  GITHUB_TOKEN       Actions 自动注入 (需 workflow 声明 contents: write)
  GITHUB_REPOSITORY  Actions 自动注入, 形如 owner/repo

流程与本机 agent.py 完全兼容: 复用同一套 /api/claim /api/progress /api/finish.
产物上传到一个固定 Release (tag: m3fetch-assets), finish 时 path = asset 的公开直链.
注意: 公开仓库的 Release asset 可被任何人列举/下载, 不具备私密性.
"""
import os
import re
import sys
import time
import subprocess
import urllib.parse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
VFETCH = os.path.join(HERE, 'vfetch.py')
PY = sys.executable
RELEASE_TAG = 'm3fetch-assets'


def env(name, required=True):
    v = os.environ.get(name, '').strip()
    if required and not v:
        raise RuntimeError('缺少环境变量 ' + name)
    return v


API_BASE = None
HDR = None
GH_REPO = None


def api(method, path, body=None, timeout=30):
    r = requests.request(method, API_BASE + path, headers=HDR,
                         json=body, timeout=timeout)
    try:
        return r.json()
    except ValueError:
        raise RuntimeError('API 非 JSON: HTTP %d %s' % (r.status_code, r.text[:200]))


def gh(method, path, body=None, content_type=None, data=None, timeout=120):
    """调 GitHub REST / Upload API. token 只从 env 读, 不回显."""
    tok = env('GITHUB_TOKEN')
    upload = path.startswith('/upload')
    host = 'https://uploads.github.com' if upload else 'https://api.github.com'
    p = path[len('/upload'):] if upload else path
    url = host + '/repos/' + GH_REPO + p
    headers = {
        'Authorization': 'Bearer ' + tok,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if content_type:
        headers['Content-Type'] = content_type
    kwargs = {'headers': headers, 'timeout': timeout}
    if data is not None:
        kwargs['data'] = data
    else:
        kwargs['json'] = body
    r = requests.request(method, url, **kwargs)
    try:
        d = r.json()
    except ValueError:
        d = {'success': False, 'raw': r.text[:300]}
    return r.status_code, d


def gh_ensure_release():
    """取(或建)固定 release, 返回 release id."""
    code, d = gh('GET', '/releases/tags/' + urllib.parse.quote(RELEASE_TAG))
    if code == 200 and d.get('id'):
        return d['id']
    code, d = gh('POST', '/releases', {
        'tag_name': RELEASE_TAG,
        'name': 'M3Fetch downloads',
        'body': '自动存放云端下载的文件。请勿手动删除。',
        'draft': False,
        'prerelease': False,
    })
    if code in (200, 201) and d.get('id'):
        return d['id']
    raise RuntimeError('创建 Release 失败: HTTP %d %s' % (code, str(d)[:300]))


def gh_upload(release_id, local_path, name):
    """删同名 asset 再上传(幂等), 返回 browser_download_url."""
    code, assets = gh('GET', '/releases/%d/assets' % release_id)
    if code == 200 and isinstance(assets, list):
        for a in assets:
            if a.get('name') == name:
                gh('DELETE', '/releases/assets/%d' % a['id'])
    url = '/upload/releases/%d/assets?name=%s' % (
        release_id, urllib.parse.quote(name))
    with open(local_path, 'rb') as f:
        code, d = gh('POST', url, content_type=guess_ct(local_path),
                     data=f, timeout=600)
    if code in (200, 201) and d.get('browser_download_url'):
        return d['browser_download_url']
    raise RuntimeError('上传 asset 失败: HTTP %d %s' % (code, str(d)[:300]))


def guess_ct(path):
    ext = os.path.splitext(path)[1].lower()
    return {
        '.mp4': 'video/mp4', '.mkv': 'video/x-matroska', '.ts': 'video/mp2t',
        '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp',
        '.gif': 'image/gif', '.bmp': 'image/bmp',
    }.get(ext, 'application/octet-stream')


def safe_name(name, fallback='media'):
    """Release asset 文件名: 去路径/危险字符, 保留中英文与常见符号."""
    name = str(name or '').strip().replace('\\', '/').split('/')[-1]
    name = re.sub(r'[<>:"|?*\x00-\x1f]', '', name).strip(' .')
    return (name or fallback)[:120]


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


def process(task, release_id):
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
        print('  上传 GitHub Release: %s (%.1f MB)' %
              (fname, size / 1048576.0), flush=True)
        public = gh_upload(release_id, local, fname)
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
        # 清理临时产物 (Release 已有副本)
        try:
            import shutil
            shutil.rmtree(outdir, ignore_errors=True)
        except Exception:
            pass


def main():
    global API_BASE, HDR, GH_REPO
    API_BASE = env('API_BASE').rstrip('/')
    HDR = {'X-Agent-Token': env('AGENT_TOKEN')}
    env('GITHUB_TOKEN')
    GH_REPO = env('GITHUB_REPOSITORY')
    print('云端执行器启动 (存储: GitHub Releases)', flush=True)
    release_id = gh_ensure_release()
    print('Release 就绪: id=%s tag=%s' % (release_id, RELEASE_TAG), flush=True)
    max_jobs = int(os.environ.get('MAX_JOBS', '20'))
    n = 0
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
        process(d['task'], release_id)
        n += 1
    print('本次共处理 %d 个任务' % n, flush=True)


if __name__ == '__main__':
    main()
