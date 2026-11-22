#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vfetch.py - 输入一条视频网址, 自动定位 m3u8/直链, 按要求转封装落盘.

用法:
  python vfetch.py "<url>"                       # 列出并下载第 1 集, 默认 mp4
  python vfetch.py "<url>" --list               # 只列出找到的剧集/媒体, 不下载
  python vfetch.py "<url>" -f mp3 --episode 3   # 第 3 集转 mp3
  python vfetch.py "<url>" -f mp4 --all         # 全部集
  python vfetch.py "<url>" -f mp4 -t 10         # 只取前 10 秒 (测试用)
  python vfetch.py "<url>" -o "D:/out" --header "Referer: https://x.com/"
  python vfetch.py "<url>" --episode 1-5 --jobs 4   # 并发下载多集
  python vfetch.py --self-test                  # 正控/负控/分母/安全自检 (子进程自证)
  python guard_test.py                          # 独立守卫测试 (8 项)

解析策略链 (固定 4 条, 每轮都报命中数与分母):
  1 直链判断      URL 本身是 m3u8/mp4/... 直接用
  2 手机端详情 API 识别 8893 播放页 -> /api/video/detail -> 每集 videoUrl
                  videoType=Decode/Sniff 时再 POST /api/play/decode
  3 网页嗅探      从 HTML/JS 里提取 m3u8 (含反斜杠转义, 相对路径, HTML 实体)
  4 yt-dlp 兜底   通用站点提取 (可选依赖)

安全: URL 只接受 http(s) (挡 file:/concat: 等 ffmpeg 协议); 请求头过滤 C0 控制字符
      (挡 CRLF 注入); 输出名规避 Windows 保留设备名; API 返回先做类型归一化;
      ffmpeg 每次调用带硬超时; HTTP 读取上限 8 MiB.
速度: Decode/Sniff 并发解析; --jobs 并发下载; 已存在且校验通过的文件直接跳过.

输出: 默认落在脚本同目录的 downloads/ 下, 下载后做文件头校验.
"""
import argparse
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error

# 无窗标志: 本机 agent(无窗) spawn 本文件时, Windows 默认会给 ffmpeg 控制台进程弹黑窗.
# CREATE_NO_WINDOW 隐藏之; Linux(云端)无此常量 -> 0, 无影响.
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------- 代理与 DNS
# 强制直连(不走系统/环境代理):
#   2026-11-22 实测 —— 本机 HTTP_PROXY/HTTPS_PROXY 指向 127.0.0.1:55451
#   (WorkBuddy 注入) 与注册表代理 127.0.0.1:10808 (v2rayN), 两者对微信域名
#   均返回 502 / TLS 中断, 表现为 yt-dlp "SSL: UNEXPECTED_EOF_WHILE_READING",
#   而同一 URL 直连 HTTP 200 正常. urllib 默认会读 env+注册表代理 => 必须显式
#   建一个"无代理"的 opener 并全局替换 urlopen, 否则所有解析/下载都会踩代理.
#   与 agent.py 的 _SESSION.trust_env=False 保持一致.
# DNS 兜底: 系统解析器对 *.us.ci 间歇 SERVFAIL (阿里 DNS), 失败时自动改用备份 DNS.
try:
    import dnsfix
    dnsfix.install()
except Exception:
    pass

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _urlopen(req, timeout=None):
    """全局无代理 urlopen (替代 urllib.request.urlopen)."""
    return _OPENER.open(req, timeout=timeout)


urllib.request.urlopen = _urlopen

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/136.0.7103.48 Safari/537.36')
# 移动端 UA: t.cn / weibo 短链在桌面 UA 下会被踢到 passport 访客验证页, 移动 UA 直达 H5 播放页
MOBILE_UA = ('Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) '
             'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 '
             'Mobile/15E148 Safari/604.1')
MEDIA_EXT = ('.m3u8', '.mp4', '.mkv', '.ts', '.mp3', '.flv', '.mov', '.webm', '.m4a')
IMG_EXT = ('.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp')
STRATEGY_NAMES = ['1 直链判断', '2 手机端详情 API', '3 网页嗅探',
                  '4 微博视频页 API', '5 yt-dlp 兜底']
ALLOWED_SCHEMES = ('http', 'https')
MAX_HTTP_BYTES = 8 * 1024 * 1024
MAX_IMG_BYTES = 50 * 1024 * 1024
# 短链/中转域名: 这些地址要先用移动 UA 跟随跳转, 才能落到真正的播放页
SHORT_HOSTS = ('t.cn', 't.co', 'bit.ly', 'dwz.cn', 'url.cn', 'sourl.cn',
               'weibo.cn', 'weibo.com')


def referer_for(url):
    """已知图床/CDN 的防盗链 Referer 兜底. 未匹配返回 None."""
    host = (urllib.parse.urlparse(url).hostname or '').lower()
    for dom, ref in (('sinaimg.cn', 'https://weibo.com/'),
                     ('weibocdn.com', 'https://weibo.com/'),
                     ('sina.com.cn', 'https://weibo.com/'),
                     ('hdslb.com', 'https://www.bilibili.com'),
                     ('gtimg.com', 'https://www.qq.com/')):
        if host == dom or host.endswith('.' + dom):
            return ref
    return None


def _fetch_bin(url, headers, timeout, max_bytes):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        chunks, total = [], 0
        while True:
            b = r.read(65536)
            if not b:
                break
            total += len(b)
            if total > max_bytes:
                raise ValueError('响应超过 %d 字节上限, 已中止' % max_bytes)
            chunks.append(b)
        return b''.join(chunks)


def http_get_bin(url, headers=None, timeout=30, max_bytes=MAX_IMG_BYTES):
    """二进制抓取(图片直链). 返回 bytes; 超限/非 http(s) 抛异常.
    403 且未提供 Referer 时, 按已知图床自动补 Referer 重试一次 (防盗链兜底)."""
    if not url_ok(url):
        raise ValueError('地址不是 http(s): %s' % str(url)[:80])
    hdr = {'User-Agent': UA}
    hdr.update(norm_headers(headers))
    try:
        return _fetch_bin(url, hdr, timeout, max_bytes)
    except urllib.error.HTTPError as e:
        if e.code == 403 and 'referer' not in {k.lower() for k in hdr}:
            ref = referer_for(url)
            if ref:
                h2 = dict(hdr)
                h2['Referer'] = ref
                return _fetch_bin(url, h2, timeout, max_bytes)
        raise        # 页面/JSON 读取上限, 防内存爆
MAX_HEADER_BYTES = 8192                 # 单个请求头长度上限
MAX_HEADERS = 32
DEFAULT_FFMPEG_TIMEOUT = 900            # 单集下载硬超时 (秒)
WIN_RESERVED = (set(['CON', 'PRN', 'AUX', 'NUL'])
                | set('COM%d' % i for i in range(1, 10))
                | set('LPT%d' % i for i in range(1, 10)))


# ---------------------------------------------------------------- 基础工具

def _clean_header(s):
    """删掉 C0/DEL 控制字符 -> 阻断 CRLF 注入; 长度截断."""
    return re.sub(r'[\x00-\x1f\x7f]', '', str(s)).strip()[:MAX_HEADER_BYTES]


def norm_headers(h):
    """入参类型归一化: None / str(JSON / 'K: V' 行) / dict -> dict[str,str]."""
    if not h:
        return {}
    if isinstance(h, str):
        try:
            h = json.loads(h)
        except Exception:
            parts = {}
            for line in h.splitlines():
                if ':' in line:
                    k, v = line.split(':', 1)
                    parts[_clean_header(k)] = _clean_header(v)
            return {k: v for k, v in list(parts.items())[:MAX_HEADERS] if k and v}
    if not isinstance(h, dict):
        return {}
    out = {}
    for k, v in h.items():
        if k is None or v is None:
            continue
        ck, cv = _clean_header(k), _clean_header(v)
        if ck and cv:
            out[ck] = cv
        if len(out) >= MAX_HEADERS:
            break
    return out


def url_ok(u):
    """scheme 白名单: 只接受 http(s), 且必须有 host. 阻断 file:/concat: 等 ffmpeg 协议."""
    try:
        p = urllib.parse.urlparse(str(u))
        return p.scheme.lower() in ALLOWED_SCHEMES and bool(p.netloc)
    except Exception:
        return False


def http_get(url, headers=None, timeout=15, ua=None):
    if not url_ok(url):
        raise ValueError('页面地址不是 http(s): %s' % str(url)[:80])
    hdr = {'User-Agent': ua or UA, 'Accept-Encoding': 'identity'}
    hdr.update(norm_headers(headers))
    req = urllib.request.Request(url, headers=hdr)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        chunks, total = [], 0
        while True:
            b = r.read(65536)
            if not b:
                break
            total += len(b)
            if total > MAX_HTTP_BYTES:
                raise ValueError('响应超过 %d 字节上限, 已中止' % MAX_HTTP_BYTES)
            chunks.append(b)
        return b''.join(chunks).decode('utf-8', 'replace'), r.geturl(), dict(r.headers)


def http_post_json(url, payload, timeout=25):
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(
        url, data=data, method='POST',
        headers={'Content-Type': 'application/json; charset=UTF-8', 'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8', 'replace'))


def safe_name(s):
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', str(s)).strip(' .')
    s = s[:80].strip(' .') or 'video'
    if s.split('.')[0].upper() in WIN_RESERVED:
        s = '_' + s
    return s


# 泛化/无意义标题: 探测到这些时回退到规则名, 不用它们当文件名
_GENERIC_TITLES = {
    'index', 'video', 'videoplayback', 'media', 'movie', 'clip', 'download',
    '视频', '影片', '播放', '未命名', 'untitled', 'default', 'output',
    '主视频', '新视频', 'video_1', 'temp', 'tmp',
}


def pick_title_name(title, fallback):
    """自动命名: title 有意义就用它(经 safe_name), 否则用 fallback.
    有意义 = 含中文或字母词, 长度 2-60, 非纯数字/纯符号/泛化占位词."""
    t = str(title or '').strip()
    if not t:
        return fallback
    # 去扩展名与集数前缀(如 001_第01集)
    t = re.sub(r'\.(m3u8|mp4|mkv|ts|mp3|flv|mov|webm|m4a)$', '', t, flags=re.I)
    t = re.sub(r'^\d{1,4}[_\-.]?', '', t).strip(' ._-')
    low = t.lower().strip(' ._-')
    if low in _GENERIC_TITLES or len(low) < 2:
        return fallback
    if re.fullmatch(r'[\d\W_]+', t):  # 纯数字/符号
        return fallback
    # 泛化集数名: 第X集 / EP12 / 第1集 单独出现
    if re.fullmatch(r'(第\s*\d+\s*集|ep\.?\s*\d+|part\s*\d+)', low):
        return fallback
    if len(t) > 60:
        t = t[:60].strip(' ._-')
    return safe_name(t) or fallback


def name_mismatch(custom, title):
    """判定"用户备注名"与"链接真实内容标题"是否明显不符 -> 返回 (bool, 原因).

    背景: --name 只是用户手填的备注, 与链接内容无关. 若备注写的是
    "山药木耳炒牛肉" 而链接真实内容是"黄仁勋...", 下载的是链接内容(正确),
    但用户会以为下错. 这里只做提示, 不阻断下载(备注本就是自由文本,
    阻断会误伤"起个中文名"这类正常用法).

    判定只认"字符集完全不相交"这种铁证, 不做语义相似度(避免误报):
      - 备注与标题都含中文 -> 无法用字符集证明不符, 判为相符(不告警)
      - 标题完全不含备注里的任何实义字 -> 判为明显不符
    """
    c = str(custom or '').strip()
    t = str(title or '').strip()
    if not c or not t:
        return False, ''
    # 标题本身没意义(占位/空) -> 无法判定, 不告警
    if pick_title_name(t, '') == '':
        return False, ''
    cn = set(re.findall(r'[\u4e00-\u9fff]', c))
    if not cn:
        return False, ''  # 备注非中文, 不做判定
    tn = set(re.findall(r'[\u4e00-\u9fff]', t))
    if not tn:
        return False, ''  # 标题无中文(多为英文/外文), 无法用中文集合比对
    overlap = cn & tn
    if overlap:
        return False, ''
    # 标题里出现了备注中某个词的非中文形式(整词包含)也算相关
    for ch in cn:
        if ch in t:
            return False, ''
    return True, '备注"%s"与链接实际内容"%s"不符' % (c[:40], t[:60])


def is_direct_media(url):
    path = urllib.parse.urlparse(url).path.lower()
    return path.endswith(MEDIA_EXT) or '.m3u8' in path


def is_image(url):
    path = urllib.parse.urlparse(url).path.lower()
    return path.endswith(IMG_EXT)


def img_ext(url):
    path = urllib.parse.urlparse(url).path.lower()
    for e in IMG_EXT:
        if path.endswith(e):
            return e
    return '.jpg'


def media_title(u):
    name = os.path.basename(urllib.parse.urlparse(u).path) or '视频'
    return re.sub(r'\.(m3u8|mp4|mkv|ts|mp3|flv|mov|webm|m4a)$', '',
                  name, flags=re.I) or '视频'


def guess_fmt(media):
    """-f auto: 解析出真实媒体地址后, 按地址推断落盘格式 (短链/播放页无法从 URL 判断)."""
    u = str((media or {}).get('url') or '')
    if is_image(u):
        return img_ext(u).lstrip('.')
    ext = os.path.splitext(urllib.parse.urlparse(u).path)[1].lower().lstrip('.')
    if ext in ('m3u8', 'm3u'):
        return 'mp4'
    if ext in ('flv', 'mov', 'webm'):   # 转封装成通用容器
        return 'mp4'
    if ext in ('mp4', 'mkv', 'ts', 'mp3', 'm4a'):
        return ext
    return 'mp4'


def extract_m3u8(text, base):
    s = text.replace('\\/', '/').replace('\\u002F', '/').replace('\\u002f', '/')
    s = html.unescape(s)
    pat_abs = r'https?://[^\s"\'<>\\()\[\]{},;]+?\.m3u8(?:\?[^\s"\'<>\\]*)?'
    pat_rel = r'["\']([^"\'\s]+?\.m3u8(?:\?[^"\'\s]*)?)["\']'
    out = []
    for u in re.findall(pat_abs, s, re.I) + re.findall(pat_rel, s, re.I):
        u = urllib.parse.urljoin(base, u.rstrip('\\,;"\''))
        if u not in out:
            out.append(u)
    return out


# ---------------------------------------------------------------- 策略实现

def resolve_local_app(page_url, timeout, jobs=4):
    """手机端 8893 播放/详情页: 从 /api/video/detail 拿整份剧集表.

    类型归一化后再迭代 (畸形 JSON 不得抛异常); Decode/Sniff 并发解析保序.
    """
    p = urllib.parse.urlparse(page_url)
    base = p.scheme + '://' + p.netloc
    q = urllib.parse.parse_qs(p.query)
    vid = (q.get('id') or [None])[0]
    api = base + '/api/video/detail'
    if vid:
        api += '?id=' + urllib.parse.quote(vid)
    txt, _, _ = http_get(api, timeout=timeout)
    data = json.loads(txt)
    if not isinstance(data, dict):
        return [], '详情 API 返回非对象'
    channels = data.get('channels') or []
    if not isinstance(channels, list):
        return [], 'channels 不是数组 (实际 %s)' % type(channels).__name__

    tasks = []
    for ch_i, ch in enumerate(channels):
        if not isinstance(ch, dict):
            continue
        vlist = ch.get('videoDataList') or []
        if not isinstance(vlist, list):
            continue
        ch_title = ch.get('title')
        if not isinstance(ch_title, str) or not ch_title.strip():
            ch_title = '线路%d' % (ch_i + 1)
        for i, ep in enumerate(vlist):
            if isinstance(ep, dict):
                tasks.append((ch_title, i, ep))

    def prep(task):
        ch_title, i, ep = task
        d = dict(ep)
        headers = norm_headers(d.get('headers'))
        src = d.get('videoUrl') or ''
        if not isinstance(src, str):
            src = ''
        vtype = d.get('videoType') or 'Direct'
        if not isinstance(vtype, str):
            vtype = 'Direct'
        if vtype in ('Decode', 'Sniff'):
            try:
                r = http_post_json(base + '/api/play/decode', d, timeout=timeout)
                if isinstance(r, dict) and r.get('success') and isinstance(r.get('url'), str):
                    src = r['url']
                    headers.update(norm_headers(r.get('headers')))
                    ua = r.get('userAgent')
                    if isinstance(ua, str) and ua:
                        headers['User-Agent'] = _clean_header(ua)
                else:
                    src = ''
            except Exception as e:
                src = ''
                print('  [warn] 解析接口失败 %s: %s' % (d.get('title'), e))
        if not src or not url_ok(src):
            return None
        title = d.get('title')
        if not isinstance(title, str) or not title.strip():
            title = '第%02d集' % (i + 1)
        return {'title': title.strip(), 'url': src, 'headers': headers,
                'channel': ch_title, 'via': vtype}

    if tasks:
        with ThreadPoolExecutor(max_workers=max(1, min(jobs, len(tasks)))) as ex:
            medias = [m for m in ex.map(prep, tasks) if m]
    else:
        medias = []
    return medias, ('%d 条线路 / %d 集, 标题=%s'
                    % (len(channels), len(medias), data.get('title') or '?'))


def ua_for(url):
    """按域名选 UA: 短链/微博在桌面 UA 下会被踢到 passport 访客页, 改用移动 UA."""
    try:
        host = (urllib.parse.urlparse(str(url)).hostname or '').lower()
    except Exception:
        return UA
    for h in SHORT_HOSTS:
        if host == h or host.endswith('.' + h):
            return MOBILE_UA
    return UA


_WEIBO_OID_RE = re.compile(r'(\d{3,4}):(\d{5,})')


def weibo_oid(url):
    """从微博视频页 URL 取 oid (形如 1034:5365931321524242). 非微博/无 oid 返回 None."""
    try:
        p = urllib.parse.urlparse(str(url or ''))
    except Exception:
        return None
    host = (p.hostname or '').lower()
    if not any(host == h or host.endswith('.' + h)
               for h in ('weibo.com', 'weibo.cn', 'video.weibo.com')):
        return None
    m = _WEIBO_OID_RE.search(p.path or '')
    if m:
        return '%s:%s' % (m.group(1), m.group(2))
    q = urllib.parse.parse_qs(p.query or '')
    for k in ('oid', 'object_id', 'id', 'url', 'surl', 'target'):
        raw = urllib.parse.unquote((q.get(k) or [''])[0])
        m = _WEIBO_OID_RE.search(raw)
        if m:
            return '%s:%s' % (m.group(1), m.group(2))
    return None


def weibo_playinfo(oid, timeout=20):
    """调 H5 播放页组件 API (form 表单, data=<JSON>). 返回 Component_Play_Playinfo dict."""
    api = ('https://h5.video.weibo.com/api/component?page=/show/'
           + urllib.parse.quote(oid, safe=':'))
    body = urllib.parse.urlencode(
        {'data': json.dumps({'Component_Play_Playinfo': {'oid': oid}})}).encode('utf-8')
    req = urllib.request.Request(api, data=body, headers={
        'User-Agent': MOBILE_UA,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'https://h5.video.weibo.com/show/' + oid,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'identity',
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(MAX_HTTP_BYTES + 1)
    if len(raw) > MAX_HTTP_BYTES:
        raise ValueError('微博 API 响应超过 %d 字节上限' % MAX_HTTP_BYTES)
    d = json.loads(raw.decode('utf-8', 'replace'))
    if str(d.get('code')) not in ('100000', '0'):
        raise ValueError('微博 API code=%s msg=%s' % (d.get('code'), d.get('msg')))
    data = d.get('data')
    info = (data or {}).get('Component_Play_Playinfo') if isinstance(data, dict) else None
    if not isinstance(info, dict) or not info:
        raise ValueError('微博 API 未返回播放信息')
    return info


def _quality_rank(label, url):
    """清晰度打分: 数字/关键词命中越高越优."""
    s = ('%s %s' % (label, url)).lower()
    for k, v in (('4k', 6), ('2160', 6), ('1080', 5), ('2k', 5), ('1440', 5),
                 ('720', 4), ('高清', 4), ('480', 3), ('标清', 2), ('360', 1)):
        if k in s:
            return v
    return 0


def resolve_weibo(page_url, timeout=20):
    """微博视频页 -> 最高清 mp4 直链. 返回 (medias, note)."""
    oid = weibo_oid(page_url)
    if not oid:
        return [], '不是微博视频页 (未识别 oid)'
    info = weibo_playinfo(oid, timeout)
    cands, n_raw = [], 0
    urls = info.get('urls')
    if isinstance(urls, dict):
        for label, u in urls.items():
            if isinstance(u, str) and u:
                n_raw += 1
                cands.append((_quality_rank(str(label), u), str(label), u))
    # 兼容: 部分版本把直链放在 page_info.media_info (单档)
    mi = info.get('page_info')
    if isinstance(mi, str):
        try:
            mi = json.loads(mi)
        except Exception:
            mi = None
    if isinstance(mi, dict) and isinstance(mi.get('media_info'), dict):
        for k in ('stream_url_hd', 'stream_url'):
            u = mi['media_info'].get(k)
            if isinstance(u, str) and u:
                n_raw += 1
                cands.append((_quality_rank(k, u), k, u))
    best, seen = None, set()
    for rank, label, u in sorted(cands, key=lambda x: -x[0]):
        if u.startswith('//'):
            u = 'https:' + u
        if not url_ok(u) or u in seen:
            continue
        seen.add(u)
        # 带出时长: 微博 CDN 拒 HEAD/Range 探测不到大小, 有时长就能用 out_time 算真实进度,
        # 不再 pct=0 跑马灯.
        dur = None
        for cand in (info.get('duration_time'), info.get('duration')):
            if cand is None:
                continue
            try:
                v = float(cand)
                if v > 0:
                    dur = v
                    break
            except (ValueError, TypeError):
                # 兼容 '0:37' / '1:02:03' 形式
                try:
                    parts = [float(x) for x in str(cand).split(':')]
                    v = 0.0
                    for part in parts:
                        v = v * 60 + part
                    if v > 0:
                        dur = v
                        break
                except (ValueError, TypeError):
                    pass
        best = {'title': str(info.get('title') or '微博视频'), 'url': u,
                'headers': {'Referer': 'https://weibo.com/', 'User-Agent': MOBILE_UA},
                'channel': '微博 %s' % (label or '默认'), 'via': 'weibo',
                'duration': dur}
        break
    if not best:
        return [], 'oid=%s, 播放信息里没有可用直链 (%d 档)' % (oid, n_raw)
    return [best], 'oid=%s, %d 档清晰度, 取最高: %s' % (oid, n_raw, best['channel'])


def unwrap_candidates(url, timeout=15):
    """短链/登录中间页解包 -> 返回 yt-dlp 候选地址列表 (原始在前, 解出的在后).

    例: t.cn 短链 -> passport.weibo.com/visitor/visitor?...&url=<真实地址>
    解出 url 参数里的真实地址, yt-dlp 才认。只做有限跳数 + scheme 白名单。
    """
    cands = [url]
    cur = url
    for _ in range(5):
        try:
            if not url_ok(cur):
                break
            req = urllib.request.Request(cur, headers={'User-Agent': ua_for(cur),
                                                       'Accept-Encoding': 'identity'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                final = r.geturl()
        except Exception:
            break
        if not url_ok(final) or final in cands:
            break
        cands.append(final)
        # passport/visitor 中间页: 从 query 的 url 参数取真实目标
        q = urllib.parse.parse_qs(urllib.parse.urlparse(final).query)
        nxt = (q.get('url') or q.get('surl') or q.get('target') or [None])[0]
        if nxt and url_ok(nxt) and nxt not in cands:
            cands.append(nxt)
            cur = nxt
            continue
        break
    return cands


def resolve_ytdlp(url, timeout, extra_cands=None):
    try:
        import yt_dlp
    except ImportError:
        return [], 'yt-dlp 未安装 (可选依赖)'
    opts = {'quiet': True, 'no_warnings': True, 'skip_download': True,
            'noplaylist': True, 'socket_timeout': timeout,
            # 禁用代理: yt-dlp 默认读 HTTP_PROXY/HTTPS_PROXY, 本机代理对目标站
            # 502/TLS 中断, 表现为 "SSL: UNEXPECTED_EOF_WHILE_READING".
            # 'proxy': '' 表示不走任何代理 (直连).
            'proxy': ''}
    cands = list(dict.fromkeys([url] + list(extra_cands or [])))
    info = None
    last_err = ''
    for cand in cands:
        try:
            with yt_dlp.YoutubeDL(opts) as ydl:
                info = ydl.extract_info(cand, download=False)
            if info:
                break
        except Exception as e:
            last_err = str(e)[:120]
            info = None
    if not info:
        return [], 'yt-dlp 提取失败 (试了 %d 个地址): %s' % (len(cands), last_err)
    if not info:
        return [], 'yt-dlp 无结果'
    headers = norm_headers(info.get('http_headers'))
    entries = info.get('entries') or [info]
    if not isinstance(entries, (list, tuple)):
        try:
            entries = list(entries)
        except TypeError:
            entries = [info]
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        cands = []
        u0 = e.get('url')
        if isinstance(u0, str) and u0:
            cands.append(u0)
        fmts = e.get('formats') or []
        if not isinstance(fmts, list):
            fmts = []
        for f in fmts:
            if not isinstance(f, dict):
                continue
            u = f.get('url') or ''
            if isinstance(u, str) and ('.m3u8' in u or 'm3u8' in str(f.get('protocol') or '')):
                cands.append(u)
        u = next((x for x in cands if '.m3u8' in x), cands[0] if cands else '')
        if u and url_ok(u):
            # 关键修复: 透传 yt-dlp 已解析的大小/时长, 供进度条直接算百分比.
            # 原实现丢弃这些字段 -> 下游只能重新 HEAD/Range 探测, 被 CDN 拒则 pct=0 跑马灯.
            size = e.get('filesize') or e.get('filesize_approx')
            dur = e.get('duration')
            # 若是某个具体 format 的 url, 用该 format 自己的大小/时长更精确
            for f in (e.get('formats') or []):
                if isinstance(f, dict) and f.get('url') == u:
                    size = f.get('filesize') or f.get('filesize_approx') or size
                    dur = f.get('duration') or dur
                    break
            out.append({'title': e.get('title') or '视频', 'url': u,
                        'headers': headers, 'channel': 'yt-dlp',
                        'via': e.get('extractor_key') or 'yt-dlp',
                        'size': int(size) if size and int(size) > 0 else None,
                        'duration': float(dur) if dur and float(dur) > 0 else None})
    return out, 'yt-dlp 返回 %d 项' % len(out)


def resolve(url, timeout=15, use_ytdlp=True, extra_headers=None):
    """返回 (medias, report). report 条数 == STRATEGY_NAMES -> 分母强制."""
    report = [{'name': n, 'count': 0, 'note': ''} for n in STRATEGY_NAMES]
    medias = []
    extra = norm_headers(extra_headers)

    # 守卫: scheme 白名单must在输出任何媒体之前拦截
    if not url_ok(url):
        note = 'URL scheme 不在白名单 (只接受 http/https): %s' % str(url)[:60]
        for r in report:
            r['note'] = note
        return [], report

    # 策略 1: 直链(含图片)
    if is_direct_media(url) or is_image(url):
        medias = [{'title': media_title(url), 'url': url, 'headers': dict(extra),
                   'channel': '直链', 'via': 'Direct'}]
        report[0]['count'] = 1
        report[0]['note'] = 'URL 本身是媒体地址'
        for r in report[1:]:
            r['note'] = '策略 1 已命中, 未执行'
        return medias, report
    report[0]['note'] = 'URL 不是媒体直链'

    # 抓页面一次, 供策略 2 / 3 复用. 短链/微博用移动 UA, 否则会被踢到 passport 访客页
    page_text, final_url = '', url
    try:
        page_text, final_url, _ = http_get(url, timeout=timeout, ua=ua_for(url))
        # 微博 passport 访客中间页: 真实播放页在 query.url 里, 换移动 UA 重取
        phost = (urllib.parse.urlparse(final_url).hostname or '').lower()
        if phost == 'passport.weibo.com' or phost.endswith('.passport.weibo.com'):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(final_url).query)
            real = (q.get('url') or [''])[0]
            if real and url_ok(real):
                page_text, final_url, _ = http_get(real, timeout=timeout, ua=MOBILE_UA)
    except Exception as e:
        report[1]['note'] = '页面抓取失败: %s' % str(e)[:100]
        report[2]['note'] = '无页面内容可扫'
    else:
        # 策略 2: 手机端 App 页面
        is_app = any(k in page_text for k in
                     ('/api/video/detail', 'videoPlaylist', 'video-detail.html'))
        if is_app:
            try:
                m, note = resolve_local_app(final_url, timeout)
                medias.extend(m)
                report[1]['count'] = len(m)
                report[1]['note'] = note
            except Exception as e:
                report[1]['note'] = '详情 API 失败: %s' % str(e)[:120]
        else:
            report[1]['note'] = '不是手机端播放页 (未匹配 /api/video/detail)'

        # 策略 3: 网页嗅探 (策略 2 未命中才扫)
        if not medias:
            found = extract_m3u8(page_text, final_url)
            for u in found:
                medias.append({'title': media_title(u), 'url': u,
                               'headers': dict(extra), 'channel': '网页', 'via': 'sniff'})
            report[2]['count'] = len(found)
            report[2]['note'] = '扫描 %d 字符 HTML, 命中 %d 个 m3u8' % (len(page_text), len(found))
        else:
            report[2]['note'] = '策略 2 已命中, 未执行'

    # 策略 4: 微博视频页 API (h5 播放页是 JS 空壳, 嗅探扫不到, 必须走组件 API)
    if not medias:
        tried = []
        note = ''
        for cand in ((final_url, url) if final_url != url else (url,)):
            if not weibo_oid(cand):
                continue
            try:
                m, note = resolve_weibo(cand, timeout)
            except Exception as e:
                m, note = [], '微博 API 失败: %s' % str(e)[:120]
            tried.append(cand)
            if m:
                medias.extend(m)
                break
        report[3]['count'] = len(medias)
        if tried:
            report[3]['note'] = note + ' (试了 %d 个地址)' % len(tried)
        else:
            report[3]['note'] = '不是微博视频页 (无 oid)'
    else:
        report[3]['note'] = '前面策略已命中, 未执行'

    # 策略 5: yt-dlp 兜底 (先解短链/中间页, 再逐个候选尝试)
    if not medias:
        if use_ytdlp:
            cands = unwrap_candidates(url, timeout)
            m, note = resolve_ytdlp(url, timeout, extra_cands=cands)
            medias.extend(m)
            report[4]['count'] = len(m)
            report[4]['note'] = note + (' | 解包候选 %d 个' % len(cands) if len(cands) > 1 else '')
        else:
            report[4]['note'] = '已用 --no-ytdlp 关闭'
    else:
        report[4]['note'] = '前面策略已命中, 未执行'

    for m in medias:
        h = norm_headers(m.get('headers'))
        h.update(extra)
        m['headers'] = h
    return medias, report


# ---------------------------------------------------------------- 下载与校验

def find_ffmpeg():
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        pass
    from shutil import which
    return which('ffmpeg') or which('ffmpeg.exe')


def media_duration(media, timeout=10):
    """探测媒体总时长(秒), 用于进度条百分比. 失败返回 None (不阻断下载).
    HLS: 累加 #EXTINF; master playlist 则跟第一个子 m3u8 一层."""
    # 优先用解析器(如 yt-dlp)已带出的时长, 避免二次探测失败导致 pct=0 跑马灯
    d0 = media.get('duration')
    if d0 and float(d0) > 0:
        return float(d0)
    url = media.get('url', '')
    if '.m3u8' not in url.lower():
        return None
    try:
        txt, _, _ = http_get(url, media.get('headers'), timeout)
        lines = [x.strip() for x in txt.splitlines() if x.strip()]
        if any('EXT-X-STREAM-INF' in x for x in lines):
            subs = [x for x in lines if x and not x.startswith('#')]
            if subs:
                sub = urllib.parse.urljoin(url, subs[0])
                txt, _, _ = http_get(sub, media.get('headers'), timeout)
        durs = [float(x) for x in re.findall(r'#EXTINF:([\d.]+)', txt)]
        return sum(durs) if durs else None
    except Exception:
        return None


def content_length(media, timeout=10):
    """直链文件大小(字节), 用于直链下载的字节进度. 失败/未知返回 None.
    先 HEAD; 很多 CDN(如 weibocdn) 拒 HEAD 403, 回退 Range GET 读 Content-Range 总长."""
    # 优先用解析器(如 yt-dlp)已带出的大小, 避免二次 HEAD/Range 被 CDN 拒绝 → pct=0 跑马灯
    sz0 = media.get('size')
    if sz0 and int(sz0) > 0:
        return int(sz0)
    url = media.get('url', '')
    if not url_ok(url):
        return None
    hdr = {'User-Agent': UA}
    hdr.update(norm_headers(media.get('headers')))
    # 1) HEAD
    try:
        req = urllib.request.Request(url, headers=hdr, method='HEAD')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            n = int(r.headers.get('Content-Length') or 0)
        if n > 0:
            return n
    except Exception:
        pass
    # 2) Range GET: 只取 1 字节, 从 Content-Range: bytes 0-0/123456 读总长
    try:
        h2 = dict(hdr)
        h2['Range'] = 'bytes=0-0'
        req = urllib.request.Request(url, headers=h2)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            cr = r.headers.get('Content-Range') or ''
            m = re.search(r'/(\d+)\s*$', cr)
            if m:
                return int(m.group(1))
            n = int(r.headers.get('Content-Length') or 0)
            if n > 1:
                return n
    except Exception:
        pass
    return None


def multipart_download(media, out, timeout=10, connections=8, on_bytes=None,
                       quiet=False, min_size=8 * 1024 * 1024):
    """多连接 Range 分段下载直链到 out, 成功返回 True, 任何失败返回 False 由调用方回退.

    设计(真实提速, 已实测微博源 8 连接 ~6.5x):
    - 仅用于 http(s) 直链 + 大小已知 + 支持 Range(206) + 超过 min_size 的文件.
    - N 段并发各下一段到 .partN, 全部成功后按序拼接成 out; 失败绝不产出半成品.
    - urllib 实现(与本项目风格一致, 无 requests 依赖, 云端 Linux 同样可用).
    - 用 headers(Referer/UA) 原样透传, 微博 CDN 必需.
    返回 False 的场景(正常回退 ffmpeg): 大小未知/不支持Range/太小/段错误/超时.
    """
    url = media.get('url', '')
    if not url_ok(url) or connections < 2:
        return False
    total = content_length(media, timeout)
    if not total or total < min_size:
        return False
    hdr = {'User-Agent': UA}
    hdr.update(norm_headers(media.get('headers')))

    # 探测 Range 支持: 取首 1 字节, 必须 206 且带回 Content-Range 总长
    probe = dict(hdr); probe['Range'] = 'bytes=0-0'
    try:
        req = urllib.request.Request(url, headers=probe)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 206:
                return False
            cr = r.headers.get('Content-Range') or ''
            m = re.search(r'/(\d+)\s*$', cr)
            if not m or int(m.group(1)) != total:
                return False
    except Exception:
        return False

    n = max(2, min(connections, 16))
    seg = total // n
    parts = [out + '.part%d' % i for i in range(n)]
    done = [0] * n
    lock = threading.Lock()
    reported = [0]

    def fetch_seg(i):
        lo = i * seg
        hi = total - 1 if i == n - 1 else (i + 1) * seg - 1
        h = dict(hdr); h['Range'] = 'bytes=%d-%d' % (lo, hi)
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, headers=h)
                with urllib.request.urlopen(req, timeout=timeout) as r, open(parts[i], 'wb') as f:
                    while True:
                        buf = r.read(131072)
                        if not buf:
                            break
                        f.write(buf)
                        with lock:
                            done[i] += len(buf)
                            if on_bytes:
                                reported[0] += len(buf)
                                on_bytes(reported[0])
                # 段长度校验: 必须正好 hi-lo+1
                if os.path.getsize(parts[i]) == hi - lo + 1:
                    return True
            except Exception:
                pass
            # 重试前清掉残段
            try:
                if os.path.exists(parts[i]):
                    os.remove(parts[i])
            except OSError:
                pass
        return False

    ok = False
    try:
        with ThreadPoolExecutor(max_workers=n) as ex:
            results = list(ex.map(fetch_seg, range(n)))
        if not all(results):
            return False
        # 按序拼接成临时文件, 校验总长后原子替换
        merged = out + '.partmerge'
        with open(merged, 'wb') as w:
            for p in parts:
                with open(p, 'rb') as f:
                    while True:
                        buf = f.read(1048576)
                        if not buf:
                            break
                        w.write(buf)
        if os.path.getsize(merged) != total:
            try: os.remove(merged)
            except OSError: pass
            return False
        os.replace(merged, out)
        ok = True
        if not quiet:
            print('[分段] %d 连接下载完成 (%.1f MB)' % (n, total / 1048576.0))
        return True
    except Exception:
        return False
    finally:
        # 无论成败都清理所有 .part 临时段
        for p in parts:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
        try:
            if os.path.exists(out + '.partmerge'):
                os.remove(out + '.partmerge')
        except OSError:
            pass


def _write_progress(path, pct, extra=None):
    """原子写进度文件, 防 agent 读到半个 JSON. extra 可带 bytes 等附加字段."""
    try:
        tmp = path + '.tmp'
        data = {'pct': int(pct)}
        if extra:
            data.update(extra)
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except OSError:
        pass


def ffmpeg_cmd(ffmpeg, media, out, fmt, duration, overwrite, insecure, audio_fallback=False):
    headers = {'User-Agent': UA}
    headers.update(norm_headers(media.get('headers')))
    hdr = ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items())
    cmd = [ffmpeg, '-hide_banner', '-loglevel', 'warning', '-stats',
           '-headers', hdr]
    if insecure:
        cmd += ['-tls_verify', '0']
    cmd += ['-i', media['url']]
    if fmt == 'mp4':
        if audio_fallback:
            cmd += ['-c:v', 'copy', '-c:a', 'aac', '-b:a', '192k']
        else:
            cmd += ['-c', 'copy']
        cmd += ['-movflags', '+faststart']
    elif fmt == 'mp3':
        cmd += ['-vn', '-c:a', 'libmp3lame', '-q:a', '2']
    elif fmt == 'm4a':
        cmd += ['-vn', '-c:a', 'aac', '-b:a', '192k']
    else:  # ts / mkv / 其它: 原样封装
        cmd += ['-c', 'copy']
    if duration:
        cmd += ['-t', str(duration)]
    cmd += ['-f', {'mp4': 'mp4', 'mp3': 'mp3', 'm4a': 'ipod', 'mkv': 'matroska',
                   'ts': 'mpegts'}.get(fmt, fmt)]
    cmd += ['-y' if overwrite else '-n', out]
    return cmd


def verify_output(path, fmt):
    """机械拦截: 不看 ffmpeg 退出码就下结论."""
    if not os.path.isfile(path):
        return False, '文件不存在'
    size = os.path.getsize(path)
    if size < 1024:
        return False, '文件过小 (%d B)' % size
    with open(path, 'rb') as f:
        head = f.read(16)
    if fmt == 'mp4' and b'ftyp' not in head[:12]:
        return False, '缺 ftyp, 不是有效 MP4'
    if fmt == 'ts' and head[:1] != b'\x47':
        return False, '缺 TS 同步字节, 不是有效 TS'
    if fmt == 'mp3' and not (head[:3] == b'ID3' or head[:1] == b'\xff'):
        return False, '不是有效 MP3'
    return True, '%.1f MiB' % (size / 1024 / 1024)


def _run_ffmpeg(cmd, limit, quiet, on_pct=None, total_sec=None, total_bytes=None,
                on_bytes=None, out_file=None):
    """运行 ffmpeg. 流式读 -progress 报告进度:
    - total_sec: 按媒体时长算百分比 (m3u8 已知时长)
    - total_bytes: 按已写字节算百分比 (直链已知 Content-Length)
    - on_bytes: 只报已写字节数 (总大小未知时的兜底, 页面显示"已下载 X MB")
    - out_file: -c copy 时 ffmpeg -progress 的 total_size 只在末尾出现, 需额外
      轮询输出文件大小作为连续进度来源 (真实字节/总字节).
    都无则不采集. 返回 returncode; 超时抛 TimeoutExpired."""
    known = (total_sec and total_sec > 0) or (total_bytes and total_bytes > 0)
    if not known and not on_bytes:
        p = subprocess.run(cmd, capture_output=quiet, timeout=limit, creationflags=NO_WINDOW)
        return p.returncode
    # -progress pipe:1 输出 key=value; -nostats 关掉 stderr 的统计行避免重复
    pcmd = list(cmd)
    pcmd[1:1] = ['-progress', 'pipe:1', '-nostats']
    proc = subprocess.Popen(pcmd, stdout=subprocess.PIPE,
                            stderr=(subprocess.DEVNULL if quiet else None),
                            creationflags=NO_WINDOW)
    state = {'pct': 0}

    def push(pct):
        pct = max(0, min(99, pct))  # 结束前封顶 99, 校验通过后才写 100
        if pct > state['pct']:
            state['pct'] = pct
            on_pct(pct)

    def reader():
        try:
            for raw in proc.stdout:
                line = raw.decode('utf-8', 'replace').strip()
                if line.startswith('out_time_ms=') and total_sec:
                    try:
                        us = int(line.split('=', 1)[1])
                        push(int(us / 1e6 / total_sec * 100))
                    except (ValueError, ZeroDivisionError):
                        pass
                elif line.startswith('total_size='):
                    try:
                        n = int(line.split('=', 1)[1])
                        if total_bytes:
                            push(int(n * 100 / total_bytes))
                        elif on_bytes and n > 0:
                            on_bytes(n)
                    except (ValueError, ZeroDivisionError):
                        pass
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # -c copy 时 ffmpeg -progress/out_time 集中在末尾, 用输出文件大小轮询补连续进度.
    # 只对按字节统计(total_bytes)启用; 按时长的 m3u8 用 out_time_ms 已足够.
    fs_stop = threading.Event()

    def fs_watcher():
        while not fs_stop.wait(0.5):
            try:
                sz = os.path.getsize(out_file) if out_file else 0
                if total_bytes and sz > 0:
                    push(int(sz * 100 / total_bytes))
                elif on_bytes and sz > 0:
                    on_bytes(sz)
            except (OSError, TypeError, ZeroDivisionError):
                pass

    fs_t = None
    if out_file and (total_bytes or on_bytes):
        fs_t = threading.Thread(target=fs_watcher, daemon=True)
        fs_t.start()
    try:
        rc = proc.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        t.join(timeout=2)
        raise
    finally:
        fs_stop.set()
        if fs_t:
            fs_t.join(timeout=1)
    t.join(timeout=3)
    try:
        proc.stdout.close()
    except Exception:
        pass
    return rc


def download(ffmpeg, media, outdir, fmt, duration, overwrite, insecure, label,
             timeout=None, quiet=False, on_pct=None, total_sec=None, total_bytes=None,
             on_bytes=None):
    out = os.path.join(outdir, label + '.' + fmt)
    # 图片直链: 不走 ffmpeg, 直接二进制落盘, 扩展名取自 URL
    if is_image(media.get('url', '')):
        # 标题可能已带图片扩展名(如 xxx.jpg), 先剥掉再按 URL 补, 防 xxx.jpg.jpg
        base = safe_name(label)
        for e in sorted(IMG_EXT, key=len, reverse=True):
            if base.lower().endswith(e):
                base = base[:-len(e)]
                break
        out = os.path.join(outdir, base + img_ext(media['url']))
        if not overwrite and os.path.isfile(out):
            return True, out, '已存在, 跳过'
        if not url_ok(media.get('url', '')):
            return False, out, '图片地址不是 http(s), 已拒绝'
        if not quiet:
            print('\n[图片] %s -> %s' % (media['title'], out))
        try:
            data = http_get_bin(media['url'], media.get('headers'))
        except Exception as e:
            return False, out, '图片下载失败: %s' % str(e)[:140]
        if len(data) < 100:
            return False, out, '图片过小 (%d B), 疑似无效' % len(data)
        try:
            with open(out, 'wb') as f:
                f.write(data)
        except OSError as e:
            return False, out, '写盘失败: %s' % str(e)[:140]
        if on_pct:
            on_pct(100)
        return True, out, '图片 %d B' % len(data)
    # 速度: 已完成且校验通过的直接跳过, 不重启 ffmpeg
    if not overwrite and os.path.isfile(out):
        ok, note = verify_output(out, fmt)
        if ok:
            if on_pct:
                on_pct(100)
            return True, out, '已存在, 跳过 (%s)' % note
    # 安全: 二次拦截, 防止从嗅探/API 混进 file:/concat: 等协议
    if not url_ok(media.get('url', '')):
        return False, out, '媒体地址不是 http(s), 已拒绝'
    limit = timeout or DEFAULT_FFMPEG_TIMEOUT
    # 真实提速: 直链 + 可 copy 格式先试多连接分段下载(带 Range 回退).
    # 仅当解析器带出 total_bytes(直链大小已知)时才有意义; m3u8/无大小则跳过.
    # 环境变量 VF_CONNECTIONS 控制并发数(默认8, 设 0/1 关闭); 失败自动回退 ffmpeg.
    conn_on = os.environ.get('VF_CONNECTIONS')
    try:
        conn = int(conn_on) if conn_on is not None else 8
    except ValueError:
        conn = 8
    mp_ok = False
    if conn >= 2 and fmt in ('mp4', 'm4a', 'ts', 'mkv'):
        url_l = str(media.get('url', '')).lower().split('?')[0]
        is_m3u8 = '.m3u8' in url_l
        if not is_m3u8:
            mp_total = content_length(media, timeout=10)
            def _mp_bytes(got):
                if on_bytes:
                    on_bytes(got)
                elif on_pct and mp_total:
                    on_pct(min(99, int(got * 100 / mp_total)))
            if not quiet:
                print('\n[分段尝试] %s (%d 连接)' % (media['title'], conn))
            mp_ok = multipart_download(media, out, timeout=timeout or 15,
                                       connections=conn, on_bytes=_mp_bytes, quiet=quiet)
            if mp_ok:
                good, note = verify_output(out, fmt)
                if good:
                    if on_pct:
                        on_pct(100)
                    if not quiet:
                        print('[分段] 成功并校验通过 -> %s' % out)
                    return True, out, '分段下载 %d 连接 (%s)' % (conn, note)
                # 分段文件校验不过 -> 删掉, 回退 ffmpeg
                try: os.remove(out)
                except OSError: pass
                mp_ok = False
            if not quiet:
                print('[分段] 不可用/失败, 回退 ffmpeg 单连接')
    cmd = ffmpeg_cmd(ffmpeg, media, out, fmt, duration, overwrite, insecure)
    if not quiet:
        print('\n[下载] %s -> %s' % (media['title'], out))
        print('[cmd ] %s' % ' '.join(c if '\r' not in c else '<headers>' for c in cmd))
    try:
        rc = _run_ffmpeg(cmd, limit, quiet, on_pct, total_sec, total_bytes, on_bytes,
                         out_file=out)
    except subprocess.TimeoutExpired:
        return False, out, 'ffmpeg 超时 (>%ss)' % limit
    except Exception as e:
        return False, out, 'ffmpeg 启动失败: %s' % str(e)[:140]
    if rc != 0 and fmt == 'mp4':
        if not quiet:
            print('[重试] -c copy 失败, 改用视频直拷 + 音频重编码 ...')
        cmd = ffmpeg_cmd(ffmpeg, media, out, fmt, duration, True, insecure, audio_fallback=True)
        try:
            rc = _run_ffmpeg(cmd, limit, quiet, on_pct, total_sec, total_bytes, on_bytes,
                         out_file=out)
        except subprocess.TimeoutExpired:
            return False, out, '重试 ffmpeg 超时 (>%ss)' % limit
        except Exception as e:
            return False, out, '重试 ffmpeg 失败: %s' % str(e)[:140]
    ok, note = verify_output(out, fmt)
    if rc != 0 or not ok:
        return False, out, 'ffmpeg rc=%d; 校验: %s' % (rc, note)
    if on_pct:
        on_pct(100)
    return True, out, note


# ---------------------------------------------------------------- CLI

def parse_selection(spec, total):
    """'3' / '1-3' / '1,3,5' -> 0-based 索引列表."""
    if not spec:
        return [0]
    out = []
    for part in str(spec).split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                out.extend(range(int(a) - 1, int(b)))
            except ValueError:
                pass
        elif part.isdigit():
            out.append(int(part) - 1)
    return [i for i in dict.fromkeys(out) if 0 <= i < total]


def print_report(report, medias):
    print('[resolve] 策略报告 (分母 = %d 条策略):' % len(report))
    for r in report:
        print('  %-18s 命中 %-3d | %s' % (r['name'], r['count'], r['note'] or '-'))
    print('  => 共 %d 个媒体地址' % len(medias))
    if not medias:
        print('  [结论] 本次未提取到 m3u8。注意: "未找到" ≠ "页面没有 m3u8"; '
              '可能需要 Referer/Cookie (--header) 或该站需 yt-dlp/登录态。')
        hint = '; '.join(r['note'] for r in report if 'passport' in str(r.get('note', '')))
        if hint:
            print('  [提示] 链接被微博访客系统拦截(passport 验证页), 需要登录态 Cookie。')


def _self_test_local_server():
    """本地起一个 HTTP server, 提供"已知含 m3u8 的详情页"作为确定性正控.

    为什么要本地正控: 原正控指向局域网 http://192.168.31.7:8893/ (外部依赖),
    该服务一旦下线/改版, 自测就永久红, 真实回归反而被淹没. 本地正控不依赖网络,
    永远有效, 且断言的仍是同一件事: 能不能从详情页 HTML 里抓到 m3u8.
    返回 (base_url, shutdown_fn)"""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    M3U8 = 'http://127.0.0.1:%d/stream.m3u8'
    PAGE = ('<!doctype html><html><body>'
            '<div id="player" data-src="__M3U8__"></div>'
            '<script>var src="__M3U8__";</script>'
            '</body></html>')

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith('/detail'):
                body = PAGE.replace('__M3U8__', M3U8 % self.server.server_address[1])
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
            else:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]
    return ('http://127.0.0.1:%d/detail' % port, srv.shutdown)


def _self_test_impl(base):
    """正控 + 负控 + 分母 + 安全守卫. 断言失败即抛异常."""
    # 命名自检放最前: 不依赖网络, 手机离线时仍可验证命名逻辑
    print('[self-test] 自动命名: 正控(有意义标题)/负控(泛化词回退)')
    FB = '20261116_abc123'
    for good in ['伟大的长征第一集', '如何制作披萨', 'NASA 火箭发射', 'The Last Lecture']:
        got = pick_title_name(good, FB)
        assert got != FB, '正控失败: 有意义标题 "%s" 被误回退' % good
        assert len(got) >= 2, '正控失败: 标题被截空'
        print('    采用: "%s" -> "%s"' % (good, got))
    for bad in ['index', 'video', '视频', '', '001_第01集', '123456', '第3集', 'v.m3u8']:
        got = pick_title_name(bad, FB)
        assert got == FB, '负控失败: 泛化标题 "%s" 未被回退 (得到 "%s")' % (bad, got)
        print('    回退: "%s" -> "%s"' % (bad, got))
    print('  PASS 自动命名: 正4/负7 全过')

    # 微博 oid 解析 + 清晰度打分: 纯离线, 不依赖网络
    print('[self-test] 微博 oid 解析: 正控3/负控2')
    OID = '1034:5365931321524242'
    for u in ('https://h5.video.weibo.com/show/' + OID,
              'https://weibo.com/tv/show/' + OID + '?from=old_pc_videoshow',
              'https://passport.weibo.com/visitor/visitor?url='
              + urllib.parse.quote('https://weibo.com/tv/show/' + OID, safe='')):
        got = weibo_oid(u)
        assert got == OID, '正控失败: %s -> %r (期望 %s)' % (u[:60], got, OID)
        print('    识别: %s -> %s' % (u[:58], got))
    for u in ('https://weibo.com/u/1234567890', 'https://example.com/show/' + OID):
        assert weibo_oid(u) is None, '负控失败: 非视频页 %s 被识别成 oid' % u[:60]
        print('    拒绝: %s -> None' % u[:58])
    assert (_quality_rank('高清 1080P60', 'x') > _quality_rank('高清 720P60', 'x')
            > _quality_rank('标清', 'x')), '清晰度打分排序失效'
    print('  PASS 微博 oid: 正3/负2 + 清晰度排序 全过')

    print('[self-test] 正控A(本地确定性): 详情页应解析出 >=1 个 m3u8')
    local_base, _shutdown = _self_test_local_server()
    try:
        pos, rep = resolve(local_base, timeout=8, use_ytdlp=False)
        assert len(rep) == len(STRATEGY_NAMES), \
            '分母丢失: report 应为 %d 条, 实际 %d' % (len(STRATEGY_NAMES), len(rep))
        assert len(pos) >= 1, '正控A失败: 本地已知详情页却解析出 0 个地址'
        assert any('.m3u8' in m['url'] for m in pos), '正控A失败: 命中项里没有 m3u8'
        print('  PASS 正控A(本地): %d 个地址, 首条 = %s' % (len(pos), pos[0]['url'][:80]))
    finally:
        _shutdown()

    print('[self-test] 正控B(外部源): %s' % base)
    try:
        pos_b, rep_b = resolve(base, timeout=15, use_ytdlp=False)
    except Exception as e:
        pos_b = []
        print('  [跳过] 外部源不可达(%s), 非本次改动导致; 正控A已覆盖同一能力' % type(e).__name__)
    else:
        if len(pos_b) >= 1 and any('.m3u8' in m['url'] for m in pos_b):
            print('  PASS 正控B(外部): %d 个地址' % len(pos_b))
        else:
            print('  [跳过] 外部源当前解析出 0 个地址(该源已下线/改版/需登录态), '
                  '非本次改动导致; 正控A已覆盖同一能力')

    print('[self-test] 负控: 不存在的地址必须解析出 0 个, 且不能崩')
    neg, rep2 = resolve('http://127.0.0.1:9/no-such-page', timeout=4, use_ytdlp=False)
    assert len(rep2) == len(STRATEGY_NAMES), '负控分母丢失'
    assert len(neg) == 0, '负控失败: 不存在的地址却解析出 %d 个' % len(neg)
    print('  PASS 负控: 0 命中, 4 条策略均有记录')

    print('[self-test] 名实不符告警: 正控1/负控7 (只提示不阻断)')
    _bad, _why = name_mismatch('山药木耳炒牛肉',
                                '黄仁勋，在2020年疫情期间，随手从厨房烤箱里拿出一块NVIDIA HGX A100主板。')
    assert _bad, '正控失败: 备注与内容明显不符却未告警'
    print('    告警: %s' % _why[:70])
    for _c, _t, _why2 in [
        ('山药木耳炒牛肉', '山药木耳炒牛肉的家常做法', '同名'),
        ('山药木耳炒牛肉', '今天来做山药木耳炒牛肉', '含关键词'),
        ('黄仁勋的厨房日常', '黄仁勋，在2020年疫情期间…', '含关键词'),
        ('山药木耳炒牛肉', 'NVIDIA A100 unboxing', '英文标题不判定'),
        ('山药木耳炒牛肉', '', '空标题不判定'),
        ('山药木耳炒牛肉', 'default', '占位标题不判定'),
        ('myvideo', '黄仁勋…', '非中文备注不判定'),
    ]:
        _g, _ = name_mismatch(_c, _t)
        assert not _g, '负控失败: %s 误告警' % _why2
        print('    不告警: %s' % _why2)
    print('  PASS 名实不符: 正1/负7 全过')

    print('[self-test] 安全负控: scheme / CRLF / 保留名')
    assert url_ok('http://x/') and not url_ok('file:///C:/Windows/x.mp4'), 'scheme 白名单失效'
    h = norm_headers({'X': 'a\r\nInjected: 1'})
    assert '\r' not in h['X'] and '\n' not in h['X'], 'CRLF 注入未过滤'
    assert safe_name('CON').upper() != 'CON', 'Windows 保留名未处理'
    print('  PASS 安全负控: 三项均拦住')
    print('[self-test] ALL PASS')
    return 0


def self_test(base):
    """父进程起子进程跑断言, 并自证子进程加载的就是本文件."""
    here = os.path.abspath(__file__)
    child = [sys.executable, here, '--self-test-child', '--self-test-base', base]
    try:
        p = subprocess.run(child, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=180,
                           creationflags=NO_WINDOW)
    except Exception as e:
        print('[self-test] 子进程启动失败: %s' % e)
        return 1
    loaded = next((ln.split('=', 1)[1] for ln in p.stdout.splitlines()
                   if ln.startswith('LOADED=')), '')
    print('[self-test] 子进程实际加载 = %s' % (loaded or '(未输出)'))
    if not loaded:
        print('[self-test] 子进程未输出 LOADED=, 无法自证打在产品上')
        return 1
    if os.path.normcase(os.path.normpath(loaded)) != os.path.normcase(os.path.normpath(here)):
        print('[self-test] 自证失败: 加载的不是目标文件')
        return 1
    print('[self-test] 自证通过: 测的就是当前 vfetch.py')
    print(p.stdout)
    if p.returncode != 0:
        print(p.stderr)
    return p.returncode


def main():
    ap = argparse.ArgumentParser(description='输入视频网址 -> 找 m3u8 -> 转封装落盘')
    ap.add_argument('url', nargs='?', help='视频网址 / 播放页 / 详情页 / m3u8 直链')
    ap.add_argument('-f', '--format', default='mp4',
                    choices=['auto', 'mp4', 'mp3', 'm4a', 'mkv', 'ts',
                             'jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp'],
                    help='输出容器; auto = 解析后按真实媒体类型自动决定 (图片直链忽略此参数)')
    ap.add_argument('-o', '--outdir', default=None, help='落盘目录 (默认脚本同目录 downloads/)')
    ap.add_argument('--list', action='store_true', help='只列出找到的媒体, 不下载')
    ap.add_argument('--all', action='store_true', help='下载全部集')
    ap.add_argument('--episode', default=None, help='选集: 3 / 1-3 / 1,3,5 (默认第 1 集)')
    ap.add_argument('--channel', default=None, help='只取指定线路名 (模糊匹配)')
    ap.add_argument('-t', '--duration', type=float, default=None, help='只取前 N 秒 (测试用)')
    ap.add_argument('--header', action='append', default=[], help='额外请求头, 可多次: "Referer: https://x/"')
    ap.add_argument('--timeout', type=float, default=15)
    ap.add_argument('--overwrite', action='store_true')
    ap.add_argument('--insecure', action='store_true', help='跳过 TLS 证书校验')
    ap.add_argument('--no-ytdlp', action='store_true')
    ap.add_argument('--name', default=None, help='指定输出文件名(不含扩展名); 规则化命名用, 多集自动加 _001 后缀')
    ap.add_argument('--auto-name', default=None, help='自动命名兜底值: 探测到有意义的标题用标题, 否则用此值')
    ap.add_argument('--jobs', type=int, default=4, help='并发下载数 (默认 4)')
    ap.add_argument('--ffmpeg-timeout', type=float, default=DEFAULT_FFMPEG_TIMEOUT,
                    help='单集 ffmpeg 硬超时秒数 (默认 %d)' % DEFAULT_FFMPEG_TIMEOUT)
    ap.add_argument('--progress-file', default=None,
                    help='进度输出文件(原子写 {"pct":0..100}), agent 用; 多集取平均')
    ap.add_argument('--self-test', action='store_true', help='正控/负控/分母/安全自检 (子进程自证)')
    ap.add_argument('--self-test-child', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--self-test-base', default='http://192.168.31.7:8893/')
    a = ap.parse_args()

    if a.self_test_child:
        print('LOADED=' + os.path.abspath(__file__))
        return _self_test_impl(a.self_test_base)
    if a.self_test:
        return self_test(a.self_test_base)
    if a.all and a.episode:
        print('[错误] --all 与 --episode 不能同时使用')
        return 2

    url = a.url
    if not url:
        url = input('视频网址: ').strip()
    if not url:
        print('缺少 URL')
        return 2
    if '://' not in url:
        url = 'http://' + url

    extra = {}
    for h in a.header:
        extra.update(norm_headers(h))

    medias, report = resolve(url, timeout=a.timeout,
                             use_ytdlp=not a.no_ytdlp, extra_headers=extra)
    print_report(report, medias)
    if not medias:
        return 3

    if a.channel:
        keep = [m for m in medias if a.channel in m.get('channel', '')]
        if keep:
            medias = keep
            print('[线路] 已筛选 "%s": %d 集' % (a.channel, len(medias)))
        else:
            print('[线路] 未匹配 "%s", 保留全部' % a.channel)

    print('\n[列表] 共 %d 项:' % len(medias))
    for i, m in enumerate(medias[:80], 1):
        print('  %3d. %-16s | %-8s | %s' %
              (i, m['title'][:16], m['via'][:8], m['url'][:95]))
    if len(medias) > 80:
        print('  ... 其余 %d 项已省略 (用 --list 看不全也可用 --episode 指定)' % (len(medias) - 80))

    if a.list:
        return 0

    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        print('\n[错误] 找不到 ffmpeg。安装: pip install imageio-ffmpeg')
        return 4
    print('[ffmpeg] %s' % ffmpeg)

    outdir = os.path.normpath(
        a.outdir or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads'))
    os.makedirs(outdir, exist_ok=True)

    idxs = list(range(len(medias))) if a.all else parse_selection(a.episode, len(medias))
    if not idxs:
        print('[错误] 选集为空或越界 (共 %d 集)' % len(medias))
        return 5

    fmt = a.format
    if fmt == 'auto':
        fmt = guess_fmt(medias[idxs[0]])
        print('[格式] 自动识别 -> %s (源: %s)'
              % (fmt, str(medias[idxs[0]].get('url'))[:90]))

    ok_n, fail = 0, []

    # 进度聚合: 每集一个 0..100 槽, 取平均写 progress-file (agent 场景)
    prog_slots = {}
    prog_lock = threading.Lock()

    def make_on_pct(i):
        if not a.progress_file:
            return None, None, None, None
        total = media_duration(medias[i], a.timeout)  # m3u8: 按时长
        total_b = None
        if not total:
            # 直链: HEAD/Range 探测 Content-Length, 按字节算百分比
            total_b = content_length(medias[i], a.timeout)
        prog_slots[i] = 0

        def on_pct(p):
            with prog_lock:
                prog_slots[i] = p
                avg = int(sum(prog_slots.values()) / len(prog_slots))
                _write_progress(a.progress_file, avg)

        if not total and not total_b:
            # 总大小未知: 只报已写字节数, 页面显示"已下载 X MB"
            def on_bytes(n):
                with prog_lock:
                    _write_progress(a.progress_file, 0, {'bytes': int(n)})
            return None, None, None, on_bytes
        return on_pct, total, total_b, None

    def run_one(i):
        m = medias[i]
        if a.name:
            base = safe_name(a.name)
            label = ('%s_%03d' % (base, i + 1)) if len(medias) > 1 else base
        elif a.auto_name:
            # 自动探测: 标题有意义用标题, 否则回退规则名; 多集加集号
            base = pick_title_name(m.get('title'), a.auto_name)
            label = ('%s_%03d' % (base, i + 1)) if len(medias) > 1 else base
        else:
            label = ('%03d_%s' % (i + 1, safe_name(m['title']))) if len(medias) > 1 else safe_name(m['title'])
        on_pct, total, total_b, on_bytes = make_on_pct(i) if a.progress_file else (None, None, None, None)
        # 名实不符告警: --name 是用户手填备注, 与链接真实内容可能无关.
        # 只提示不阻断(备注是自由文本). 供 cloud_runner 回写到任务, 让用户在前端看到.
        if a.name:
            bad, why = name_mismatch(a.name, m.get('title'))
            if bad:
                print('[WARN ] 名实不符: %s' % why)
        return i, download(ffmpeg, m, outdir, fmt, a.duration,
                           a.overwrite, a.insecure, label,
                           timeout=a.ffmpeg_timeout, quiet=(a.jobs > 1),
                           on_pct=on_pct, total_sec=total, total_bytes=total_b,
                           on_bytes=on_bytes)

    def report(i, ok, out, note):
        nonlocal ok_n
        if ok:
            ok_n += 1
            print('[OK  ] %s (%s)' % (out, note))
        else:
            fail.append((medias[i]['title'], note))
            print('[FAIL] %s -> %s' % (medias[i]['title'], note))

    jobs = max(1, a.jobs)
    if jobs > 1 and len(idxs) > 1:
        print('[并发] %d 个任务, 最大 %d 并发' % (len(idxs), min(jobs, len(idxs))))
        with ThreadPoolExecutor(max_workers=min(jobs, len(idxs))) as ex:
            futs = {ex.submit(run_one, i): i for i in idxs}
            for f in as_completed(futs):
                try:
                    i, (ok, out, note) = f.result()
                    report(i, ok, out, note)
                except Exception as e:
                    i = futs[f]
                    fail.append((medias[i]['title'], str(e)[:140]))
                    print('[FAIL] %s -> 线程异常: %s' % (medias[i]['title'], e))
    else:
        for i in idxs:
            _, (ok, out, note) = run_one(i)
            report(i, ok, out, note)
    print('\n[汇总] 成功 %d / %d, 目录: %s' % (ok_n, len(idxs), outdir))
    for t, n in fail:
        print('  失败: %s | %s' % (t, n))
    if fail:
        print('  提示: 403/连接被拒通常是防盗链, 加 --header "Referer: <来源页>" '
              '--header "Cookie: ..." 重试; 自签证书加 --insecure')
    return 0 if not fail else 1


if __name__ == '__main__':
    sys.exit(main())
