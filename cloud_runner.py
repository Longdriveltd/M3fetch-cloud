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
import threading
import subprocess
import urllib.parse

import requests

# DNS 兜底: 避免本地/云端 DNS 抖动导致解析 *.us.ci 失败
try:
    import dnsfix
    dnsfix.install()
except Exception:
    pass

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


def gh_delete_asset(release_id, asset_name):
    """③ 删除本 Release 下指定名字的 asset. 不存在视为已删(幂等). 返回是否删成功."""
    code, assets = gh('GET', '/releases/%d/assets' % release_id)
    if code != 200 or not isinstance(assets, list):
        raise RuntimeError('列举 asset 失败: HTTP %d' % code)
    target = None
    for a in assets:
        if a.get('name') == asset_name:
            target = a.get('id')
            break
    if target is None:
        return False  # 本就没有 -> 视为已删
    code, d = gh('DELETE', '/releases/assets/%d' % target)
    if code in (200, 204):
        return True
    # 404 = 并发下已被删, 同样视为成功
    if code == 404:
        return True
    raise RuntimeError('删 asset 失败: HTTP %d %s' % (code, str(d)[:200]))


def asset_name_from_path(raw_path):
    """从任务 path(Release 直链)解析 asset 文件名; 非 http 返回 None(本机任务, 云端不处理)."""
    if not raw_path or not isinstance(raw_path, str):
        return None
    if not raw_path.lower().startswith(('http://', 'https://')):
        return None
    name = urllib.parse.unquote(urllib.parse.urlparse(raw_path).path.rstrip('/').split('/')[-1])
    # 目录穿越/非法名守卫: 只接受纯文件名
    if not name or '/' in name or '\\' in name or name.startswith('..'):
        return None
    return name


def process_deletes(release_id):
    """③ 消费删除队列中属于云端的任务: 删 Release asset + 回写 scope=cloud.
    本机任务(path 非 http)跳过, 由本机 agent 独立处理. 返回本次处理条数."""
    try:
        d = api('GET', '/deletes')
    except Exception as e:
        print('  ③ 查询删除队列失败: %s' % e, flush=True)
        return 0
    items = d.get('items') or []
    done = 0
    for it in items:
        # KV 写配额保护: 云端已确认的项不再每轮重复删/回写. 本机 agent 侧同样跳过
        # local_done 项. 双确认未齐时双方各自只写一次, 不再空转烧配额.
        if it.get('cloud_done') is True:
            continue
        jid = str(it.get('id') or '')
        raw_path = it.get('path') or ''
        name = asset_name_from_path(raw_path)
        if not name:
            continue  # 本机任务或非法路径, 交给本机 agent
        try:
            removed = gh_delete_asset(release_id, name)
            ok, err = True, ''
            print('  ③ 删云端 asset %s: %s' % (name, '已删' if removed else '本就不存在'), flush=True)
        except Exception as e:
            ok, err = False, str(e)[:200]
            print('  ③ 删云端 asset %s 失败: %s' % (name, err), flush=True)
        try:
            api('POST', '/delete-done', {'id': jid, 'ok': ok, 'err': err, 'scope': 'cloud'})
            done += 1
        except Exception as e:
            print('  ③ 删除结果回写失败: %s' % e, flush=True)
    return done


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


def _heartbeat(tid, stop_evt, claim_token=''):
    """② 下载期间每 60s 上报一次, 刷新 Worker 租约, 防止被卡死回收误杀.
    只带 phase 文字续租, 不伪造百分比(真实进度属另一议题). 失败静默, 不打断下载.
    claim_token: ③ 领取令牌, 供 Worker 拒绝过期实例回写."""
    while not stop_evt.wait(60):
        try:
            api('POST', '/progress', {'id': tid, 'phase': '云端下载中…',
                                      'claim_token': claim_token})
        except Exception:
            pass


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
    # 名实不符告警: --name 是用户手填备注, 与链接真实内容可能无关.
    # 只提示不阻断; 捕获后回写云端, 让用户在前端能直接看到"下的可能不是你以为的那条".
    warn = ''
    for ln in (r.stdout or '').splitlines():
        if ln.startswith('[WARN ] '):
            warn = ln[7:].strip()[:300]
            break
    if warn:
        print('  ⚠ %s' % warn, flush=True)
    # 产物: 优先 vfetch 自己打印的 [OK  ] 行
    for ln in (r.stdout or '').splitlines():
        if ln.startswith('[OK  ] '):
            p = ln[7:].rsplit(' (', 1)[0].strip()
            if p and os.path.isfile(p):
                return p, warn
    # 回退: 目录里最新文件
    exts = ('.mp4', '.mkv', '.ts', '.mp3', '.m4a',
            '.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp')
    files = [os.path.join(outdir, f) for f in os.listdir(outdir)
             if os.path.splitext(f)[1].lower() in exts]
    if not files:
        raise RuntimeError('未找到落盘产物')
    return max(files, key=os.path.getmtime), warn


def process(task, release_id):
    tid = task['id']
    t0 = time.time()
    outdir = os.path.join(HERE, '_tmp', tid)
    os.makedirs(outdir, exist_ok=True)
    stop_evt = threading.Event()
    hb = threading.Thread(target=_heartbeat,
                          args=(tid, stop_evt, task.get('claim_token', '')), daemon=True)
    try:
        print('领取任务 %s: %s [%s]' % (tid, task['url'], task.get('fmt')), flush=True)
        try:
            api('POST', '/progress', {'id': tid, 'phase': '云端解析中…',
                                      'claim_token': task.get('claim_token', '')})
        except Exception:
            pass
        hb.start()  # ② 下载期间续租, 防大文件被卡死回收误杀
        local, warn = run_vfetch(task, outdir)
        size = os.path.getsize(local)
        # asset 名强制带任务号前缀: 不同任务永不撞名 (GitHub Release asset 名全局唯一,
        # 同名上传会 422 already_exists; 靠"先删后传"在并发/最终一致性下不可靠).
        base = safe_name(task.get('name') or os.path.basename(local), tid)
        ext = os.path.splitext(local)[1]
        # vfetch 对无标题链接会产出 default 占位名, 这种不算有效 basename
        if base.lower() in ('default', 'output', 'video', 'media') or base == tid:
            base = ''
        base = base[:100]
        # asset 名以任务号开头(保证唯一), 有有效标题再拼上去
        fname = (('%s_%s' % (tid, base)) if base else tid)[:120]
        if not fname.lower().endswith(ext):
            fname += ext
        print('  上传 GitHub Release: %s (%.1f MB)' %
              (fname, size / 1048576.0), flush=True)
        public = gh_upload(release_id, local, fname)
        api('POST', '/finish', {'id': tid, 'ok': True, 'path': public,
                                'size': size, 'secs': round(time.time() - t0, 1),
                                'warn': warn, 'claim_token': task.get('claim_token', '')})
        print('  完成 -> %s' % public, flush=True)
    except Exception as e:
        print('  任务 %s 失败: %s' % (tid, e), flush=True)
        try:
            api('POST', '/finish', {'id': tid, 'ok': False, 'err': str(e)[:500],
                                    'claim_token': task.get('claim_token', '')})
        except Exception as e2:
            print('  回写失败状态也失败: %s' % e2, flush=True)
    finally:
        stop_evt.set()  # ② 下载结束(成功/失败)停心跳, 避免覆盖终态
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
    # ③ 先处理删除队列(云端 asset 清理), 与下载任务无关, 独立跑一次
    try:
        nd = process_deletes(release_id)
        print('③ 本轮清理云端 asset %d 项' % nd, flush=True)
    except Exception as e:
        print('③ 删除队列处理异常(不影响下载): %s' % e, flush=True)
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


def self_test():
    """无需网络的纯逻辑自测: asset 名解析 + 双确认出队判定(与 Worker 同规则)."""
    tests = []

    # 正控: https 直链能解析出 asset 名(带任务号前缀, 与上传 fname 一致)
    u = 'https://github.com/Longdriveltd/M3fetch-cloud/releases/download/m3fetch-assets/mwn5ivougp8co_.mp4'
    tests.append(('正控-解析asset名', asset_name_from_path(u) == 'mwn5ivougp8co_.mp4'))
    # 含 URL 编码的中文名
    u2 = 'https://github.com/o/r/releases/download/tag/abc_%E4%B8%AD%E6%96%87.mp4'
    tests.append(('正控-URL解码', asset_name_from_path(u2) == 'abc_中文.mp4'))
    # 负控: 本机路径 / 空值 / 目录穿越 必须 None(云端不处理)
    tests.append(('负控-本机路径', asset_name_from_path('C:\\M3fectch\\x.mp4') is None))
    tests.append(('负控-空值', asset_name_from_path('') is None))
    tests.append(('负控-目录穿越', asset_name_from_path(
        'https://x/y/download/tag/..%2F..%2Fevil.mp4') is None))

    # 双确认出队判定(镜像 Worker delete-done 的规则)
    def all_done(item, who, ok):
        field = 'cloud_done' if who == 'cloud' else 'local_done'
        err = ''
        gone = bool(ok) or bool(__import__('re').search(r'404|不存在|not found', err, __import__('re').I))
        if not gone:
            return False
        it = dict(item)
        if 'local_done' not in it: it['local_done'] = False
        if 'cloud_done' not in it:
            it['cloud_done'] = not str(it.get('path', '')).lower().startswith(('http://', 'https://'))
        it[field] = True
        return bool(it['local_done'] and it['cloud_done'])

    cloud_item = {'id': 't1', 'path': u}
    local_item = {'id': 't2', 'path': '/data/M3fectch/x.mp4'}
    # 云端任务: 单方都不够, 双方都到齐才出队
    tests.append(('双确认-云端仅local', all_done(cloud_item, 'local', True) is False))
    tests.append(('双确认-云端仅cloud', all_done(cloud_item, 'cloud', True) is False))
    tests.append(('双确认-云端双方', all_done(
        {'id': 't1', 'path': u, 'local_done': True, 'cloud_done': False},
        'cloud', True) is True))
    # 本机任务: cloud_done 初始即真, 本机确认即出队
    tests.append(('双确认-本机local即出队', all_done(local_item, 'local', True) is True))
    # 失败不确认
    tests.append(('双确认-失败不打勾', all_done(cloud_item, 'cloud', False) is False))

    ok_n = sum(1 for _, r in tests if r)
    for name, r in tests:
        print('  [%s] %s' % ('PASS' if r else 'FAIL', name))
    print('self-test %d/%d' % (ok_n, len(tests)))
    return 0 if ok_n == len(tests) else 1


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        raise SystemExit(self_test())
    main()
