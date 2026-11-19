"""零凭证下载探针: 在 GitHub Actions 机房 IP 上实测能否下载常见站点.
不碰 KV / R2 / 任何 secret. 只回答一个问题: 机房 IP 能不能下?
"""
import os
import sys
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
VFETCH = os.path.join(HERE, 'vfetch.py')
PY = sys.executable
OUT = os.path.join(HERE, '_probe_out')

# 覆盖三类真实场景: 音乐平台 / 微博短链 / 公开视频直链
TESTS = [
    ('网易云音乐', 'https://music.163.com/#/song?id=93661', 'mp3'),
    ('微博视频', 'http://t.cn/AXTh4SEm', 'auto'),
    ('公开视频直链', 'https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4', 'mp4'),
]


def probe_one(name, url, fmt):
    od = os.path.join(OUT, name)
    os.makedirs(od, exist_ok=True)
    cmd = [PY, VFETCH, url, '-f', fmt, '-o', od, '--overwrite',
           '--auto-name', 'probe']
    print('\n===== 测试: %s =====' % name, flush=True)
    print('URL: %s' % url, flush=True)
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        tail = '\n'.join((r.stdout or '').splitlines()[-15:])
        if tail:
            print(tail, flush=True)
        files = [os.path.join(od, f) for f in os.listdir(od)
                 if os.path.getsize(os.path.join(od, f)) > 1024]
        if r.returncode == 0 and files:
            sz = sum(os.path.getsize(f) for f in files) / 1048576.0
            print('[结果] %s: ✅ 成功 (%.1f MB, %.1fs)' %
                  (name, sz, time.time() - t0), flush=True)
            return True
        print('[结果] %s: ❌ 失败 rc=%d | %s' %
              (name, r.returncode, (r.stderr or '')[-200:]), flush=True)
        return False
    except subprocess.TimeoutExpired:
        print('[结果] %s: ❌ 超时(300s)' % name, flush=True)
        return False
    except Exception as e:
        print('[结果] %s: ❌ 异常 %s' % (name, e), flush=True)
        return False


def main():
    print('云端下载探针启动 (机房 IP 实测)', flush=True)
    print('Python: %s' % PY, flush=True)
    ok = 0
    for name, url, fmt in TESTS:
        if probe_one(name, url, fmt):
            ok += 1
    print('\n===== 汇总: %d/%d 成功 =====' % (ok, len(TESTS)), flush=True)
    if ok == len(TESTS):
        print('结论: 机房 IP 下载正常, 可继续搭建云端执行器', flush=True)
    elif ok > 0:
        print('结论: 部分站点可下, 需针对失败站点加策略或代理', flush=True)
    else:
        print('结论: 机房 IP 被封, 此方案不可行, 需换方案', flush=True)
    return 0


if __name__ == '__main__':
    main()
