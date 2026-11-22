"""DNS 兜底: 系统解析失败时自动改用备份 DNS 解析 (不依赖管理员权限).

背景 (2026-11-22 实测):
  阿里 DNS 223.5.5.5 对母域 `us.ci` 间歇返回 SERVFAIL (12 次里 8-11 次失败),
  因此 `*.us.ci` (含 uniqcard.us.ci) 在系统解析器上会随机 getaddrinfo 失败 ->
  agent / m3open 报 ConnectionError -> 网页"点了没反应"、任务重试跑不动.
  8.8.8.8 / 114.114.114.114 对同一域名 12/12 稳定.

本模块做法:
  1. 先用系统默认解析 (socket.getaddrinfo);
  2. 失败 -> 直接对备份 DNS 服务器发 UDP 查询, 拿到 A 记录;
  3. 把结果缓存, 并把 socket.getaddrinfo 换成"系统优先、失败兜底"的版本.

用法: 在入口脚本最前面 `import dnsfix; dnsfix.install()`.
不改系统网卡设置, 不需要管理员权限.
"""
import socket
import struct
import threading

# 备份 DNS. 顺序按 2026-11-22 实测稳定性排:
#   119.29.29.29 (腾讯 DNSPod) 12/12  8.8.8.8 12/12  114.114.114.114 12/12
#   1.1.1.1            仅 9/12 (超时偏多) -> 放最后
#   223.5.5.5 (阿里)    对 *.us.ci 间歇 SERVFAIL -> 不作为兜底
#
# ⚠️ 污染问题 (2026-11-22 实测): 国内 DNS 会对 github.com 返回污染 IP
#   (57.155.223.240 / 57.155.223.241), 8.8.8.8 对 codeload.github.com 也污染.
#   被污染的 IP 时通时不通, 靠连通性判断不可靠 -> 用"域名可信网段"白名单校验,
#   命中白名单则该结果直接丢弃并换下一个 DNS.
FALLBACK_DNS = (
    '119.29.29.29',
    '114.114.114.114',
    '8.8.8.8',
    '1.1.1.1',
)

# 域名 -> 可信 IP 网段. 只列实测确认的官方网段 (GitHub/Azure/Cloudflare).
# 命中黑名单外的可疑段 => 视为污染, 换 DNS 重查.
_TRUSTED_NETS = {
    # GitHub 主站实测网段 (20.x / 140.82.x); 20.6/20.172/20.205/20.247 均出现过
    'github.com': ('20.', '140.82.'),
    'githubusercontent.com': ('185.199.',),
    'githubassets.com': ('185.199.',),
    'github.io': ('185.199.',),
    'githubapp.com': ('140.82.', '20.'),
    'githubusercontent.net': ('185.199.',),
}
# 已知污染段 (57.155.223.240-241 等) —— 显式拉黑, 避免误信
_BLOCKED_PREFIX = ('57.155.223.',)

QUERY_TIMEOUT = 3.0
TTL_SEC = 300

_lock = threading.Lock()
_cache = {}          # host -> (ip, expire_at)
_installed = False
_orig_getaddrinfo = None


def _build_query(name, qtype=1):
    hdr = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    labels = []
    for p in name.split('.'):
        try:
            labels.append(p.encode('idna'))
        except Exception:
            labels.append(p.encode('ascii', 'ignore'))
    qname = b''.join(bytes([len(p)]) + p for p in labels) + b'\x00'
    return hdr + qname + struct.pack('>HH', qtype, 1)


def _parse_a(data):
    """从 DNS 响应里取第一条 A 记录; 失败返回 None."""
    if len(data) < 12:
        return None
    if (data[3] & 0x0F) != 0:            # rcode != 0 (SERVFAIL=2) -> 视为失败
        return None
    ancount = struct.unpack('>H', data[6:8])[0]
    if ancount == 0:
        return None
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    i += 1 + 4                          # 跳过 qname + qtype/qclass
    for _ in range(ancount):
        if i >= len(data):
            break
        if (data[i] & 0xC0) == 0xC0:    # 压缩指针
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            i += 1
        if i + 10 > len(data):
            return None
        rtype, _cls, _ttl, rdlen = struct.unpack('>HHIH', data[i:i + 10])
        i += 10
        rdata = data[i:i + rdlen]
        i += rdlen
        if rtype == 1 and rdlen == 4:
            return '.'.join(str(b) for b in rdata)
    return None


def _query_dns(server, name, timeout=QUERY_TIMEOUT):
    """向指定 DNS 服务器发一次 A 查询, 返回 IP 字符串或 None."""
    try:
        fam = socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        s.sendto(_build_query(name), (server, 53))
        data, _ = s.recvfrom(4096)
        return _parse_a(data)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def _ip_suspicious(host, ip):
    """判断该 IP 是否像是 DNS 污染结果.

    判据 (2026-11-22 实测):
      1. 显式黑名单段 (57.155.223.* 实测被污染)
      2. 域名有已知可信网段时, 结果不在白名单 => 不可信
    """
    if not ip:
        return True
    for bad in _BLOCKED_PREFIX:
        if ip.startswith(bad):
            return True
    h = (host or '').lower()
    for suffix, prefixes in _TRUSTED_NETS.items():
        if h == suffix or h.endswith('.' + suffix):
            return not any(ip.startswith(p) for p in prefixes)
    return False


def _candidates(name):
    """收集各备份 DNS 返回的全部候选 A 记录 (去重, 过滤污染段)."""
    out = []
    for srv in FALLBACK_DNS:
        ip = _query_dns(srv, name)
        if ip and ip not in out and not _ip_suspicious(name, ip):
            out.append(ip)
    return out


def _tls_ok(ip, host, timeout=4.0):
    """TLS 握手是否成功 (仅 TCP 可连不够!).

    实测 (2026-11-22): GitHub 的部分 A 记录 (20.6.7.17 / 20.205.243.166)
    TCP 能连上, 但 TLS 握手超时 -> 客户端表现为 "Empty reply from server".
    因此解析结果必须过 TLS 校验, 否则照样连不通.
    """
    import ssl
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
    except Exception:
        return False
    try:
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(raw, server_hostname=host)
        ss.close()
        return True
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return False


def resolve_verified(name):
    """返回经 TLS 握手验证的 IP; 无可用则返回 None.

    背景: 部分站点会返回"TCP 可连但 TLS 握手超时"的死 IP
    (实测 GitHub 20.6.7.17 / 20.205.243.166). 只做 DNS 解析不够, 必须握手验证.
    """
    now = _now()
    with _lock:
        hit = _cache.get(name)
        if hit and hit[1] > now:
            return hit[0]
    cands = _candidates(name)
    for ip in cands:
        if _tls_ok(ip, name):
            with _lock:
                _cache[name] = (ip, _now() + TTL_SEC)
            return ip
    if not cands:
        # 候选全被污染过滤 => 放宽后取原始结果, 仍做 TLS 校验
        for srv in FALLBACK_DNS:
            ip = _query_dns(srv, name)
            if ip:
                cands.append(ip)
                break
        for ip in cands:
            if _tls_ok(ip, name):
                with _lock:
                    _cache[name] = (ip, _now() + TTL_SEC)
                return ip
    if cands:
        # 没有一个通过 TLS 校验 (可能站点确实要求代理/客户端证书) ->
        # 仍返回首个候选, 让上层自己报错, 不要静默失败.
        with _lock:
            _cache[name] = (cands[0], _now() + TTL_SEC)
        return cands[0]
    return None


def resolve_fallback(name):
    """系统解析失败时的兜底解析; 依次尝试备份 DNS, 返回 IP 或 None.

    对 https 类域名会做 TLS 握手校验, 跳过"TCP 可连但握手超时"的死 IP.
    """
    if not name:
        return None
    if isinstance(name, bytes):
        name = name.decode('ascii', 'ignore')
    now = _now()
    with _lock:
        hit = _cache.get(name)
        if hit and hit[1] > now:
            return hit[0]
    ip = resolve_verified(name)
    if ip:
        with _lock:
            _cache[name] = (ip, _now() + TTL_SEC)
    return ip


def _now():
    import time
    return time.time()


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror:
        pass
    ip = resolve_fallback(host)
    if not ip:
        raise socket.gaierror(socket.EAI_NONAME,
                              'dnsfix: 系统解析失败且备份 DNS 也未命中: %s' % host)
    fam = socket.AF_INET
    if family == socket.AF_INET6:
        fam = socket.AF_INET6
    return [(fam, socket.SOCK_STREAM, proto if proto else 6, '',
             (ip, port) if fam == socket.AF_INET else (ip, port, 0, 0))]


def install():
    """安装兜底解析 (幂等)."""
    global _installed, _orig_getaddrinfo
    if _installed:
        return
    _orig_getaddrinfo = socket.getaddrinfo
    socket.getaddrinfo = _patched_getaddrinfo
    _installed = True


if __name__ == '__main__':
    import sys
    install()
    hosts = sys.argv[1:] or ['uniqcard.us.ci', 'github.com']
    ok = True
    for h in hosts:
        try:
            r = socket.getaddrinfo(h, 443, socket.AF_INET)
            ip = r[0][4][0]
            print('OK   %-24s -> %s' % (h, ip))
        except Exception as e:
            ok = False
            print('FAIL %-24s -> %r' % (h, e))
    # 负控: 不存在的域名必须抛 gaierror, 不能被兜底"猜"出 IP
    try:
        socket.getaddrinfo('this-host-should-not-exist-9d8f2a.invalid', 443)
        print('FAIL 负控: 不存在的域名竟然解析成功')
        ok = False
    except socket.gaierror:
        print('OK   负控: 不存在的域名正确抛 gaierror')
    sys.exit(0 if ok else 1)
