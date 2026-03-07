#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio, base64, json, logging, os, signal, socket, sys, uuid, ipaddress, datetime, time, contextlib
from collections import deque
from contextlib import closing
from typing import Dict, Any, Optional, Tuple, List
from aiohttp import web, WSMsgType
from logging.handlers import TimedRotatingFileHandler

# ===== 로깅(일별 회전) =====
LOG_DIR = os.getenv("LOG_DIR", "/var/log/tunneler")
os.makedirs(LOG_DIR, exist_ok=True)

root_logger = logging.getLogger()
root_logger.setLevel(os.getenv("LOG_LEVEL","INFO"))
fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
file_handler = TimedRotatingFileHandler(
    filename=os.path.join(LOG_DIR, "server.log"),
    when="midnight", interval=1, backupCount=30, encoding="utf-8"
)
file_handler.setFormatter(fmt)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(fmt)
root_logger.handlers = [file_handler, stream_handler]

logger = logging.getLogger("tunnel-server")

DEFAULT_BOT_RULES = [
    "bot",
    "crawl",
    "spider",
    "slurp",
    "archiver",
    "facebookexternalhit",
    "preview",
    "headless",
    "phantom",
    "selenium",
    "scrapy",
    "python-requests",
    "wget",
]

# ===== 전역 상태 =====
TUNNELS: Dict[str, Dict[str, Any]] = {}   # subdomain -> {ws, tcp:{}, udp:{}}
PENDING: Dict[str, asyncio.Future] = {}   # HTTP 프록시 응답 대기
CONTROL_PENDING: Dict[str, asyncio.Future] = {}  # 클라이언트 제어 응답 대기
ADMIN_WSS: List[web.WebSocketResponse] = []  # 대시보드 실시간 구독자(관리자 WS)
ADMIN_SESSIONS: Dict[str, float] = {}  # session_token -> expires_at
BOT_IP_FLAGS: Dict[str, Dict[str, Any]] = {}
BOT_ACCESS_RECENT: Dict[str, deque] = {}

APP_NAME = "tunneler-server"

def app_version(default: str="dev") -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.getenv("TUNNELER_VERSION_FILE", "").strip(),
        os.path.join(base_dir, "VERSION"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return value
        except Exception:
            continue
    return default

APP_VERSION = app_version()

# 실시간 대역폭(초당 누적)
_bw_counters: Dict[str, Dict[str, int]] = {}
_bw_total: Dict[str, int] = {"tx":0, "rx":0}

def _bw_acc(sub: str, key: str, n: int):
    n = max(0, int(n))
    c = _bw_counters.setdefault(sub or "_", {"tx":0,"rx":0})
    c[key] = c.get(key,0) + n
    _bw_total[key] = _bw_total.get(key,0) + n

# === 사용량 집계(디스크 저장) ===
USAGE_FILE = os.getenv("USAGE_FILE", "/opt/tunneler/usage.json")
def _load_usage():
    if not os.path.exists(USAGE_FILE): return {}
    try:
        with open(USAGE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}
USAGE: Dict[str, Any] = _load_usage()
_usage_dirty = False
_last_usage_save = 0.0

def _date_keys(now: Optional[datetime.datetime]=None):
    if now is None: now = datetime.datetime.now()
    day = now.strftime("%Y-%m-%d")
    week = f"{now.strftime('%G')}-W{now.strftime('%V')}"
    month = now.strftime("%Y-%m")
    return day, week, month

def _add_usage(sub: str, tx: int, rx: int, now: Optional[datetime.datetime]=None):
    global _usage_dirty
    day, week, month = _date_keys(now)
    u = USAGE.setdefault(sub, {"daily":{}, "weekly":{}, "monthly":{}})
    for bucket, key in (("daily",day), ("weekly",week), ("monthly",month)):
        d = u[bucket].setdefault(key, {"tx":0,"rx":0})
        d["tx"] += max(0,int(tx))
        d["rx"] += max(0,int(rx))
    _usage_dirty = True

def _save_usage_if_needed(force=False):
    global _usage_dirty, _last_usage_save
    now = time.time()
    if not force and (not _usage_dirty or now - _last_usage_save < 5.0):
        return
    tmp = USAGE.copy()
    try:
        os.makedirs(os.path.dirname(USAGE_FILE), exist_ok=True)
        with open(USAGE_FILE, "w", encoding="utf-8") as f:
            json.dump(tmp, f, ensure_ascii=False, indent=2)
        _last_usage_save = now
        _usage_dirty = False
    except Exception as e:
        logger.warning("usage save failed: %s", e)

def _get_usage_slice(sub: str, period: str, limit: int=30):
    u = USAGE.get(sub, {})
    b = u.get(period, {})
    keys = list(b.keys()); keys.sort()
    if limit > 0: keys = keys[-limit:]
    items = [{"key":k, "tx":b[k]["tx"], "rx":b[k]["rx"], "total": b[k]["tx"]+b[k]["rx"]} for k in keys]
    return items

# === 접속 IP 기록 ===
IP_HISTORY_FILE = os.getenv("IPHIST_FILE", "/opt/tunneler/ip_history.json")
IPHIST_TIMES_FILE = os.getenv("IPHIST_TIMES_FILE", "/opt/tunneler/ip_history_times.json")

def _load_json(path: str, default):
    if not os.path.exists(path): return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

IP_HISTORY: Dict[str, Dict[str, List[str]]] = _load_json(IP_HISTORY_FILE, {})
IP_TIMES: Dict[str, Dict[str, Dict[str, List[str]]]] = _load_json(IPHIST_TIMES_FILE, {})
_ip_hist_dirty = False
_last_ip_hist_save = 0.0
_ip_times_dirty = False
_last_ip_times_save = 0.0

def _save_ip_hist_if_needed(force=False):
    global _ip_hist_dirty, _last_ip_hist_save
    now = time.time()
    if not force and (not _ip_hist_dirty or now - _last_ip_hist_save < 5.0): return
    try:
        os.makedirs(os.path.dirname(IP_HISTORY_FILE), exist_ok=True)
        with open(IP_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(IP_HISTORY, f, ensure_ascii=False, indent=2)
        _last_ip_hist_save = now
        _ip_hist_dirty = False
    except Exception as e:
        logger.warning("ip_history save failed: %s", e)

def _save_ip_times_if_needed(force=False):
    global _ip_times_dirty, _last_ip_times_save
    now = time.time()
    if not force and (not _ip_times_dirty or now - _last_ip_times_save < 5.0): return
    try:
        os.makedirs(os.path.dirname(IPHIST_TIMES_FILE), exist_ok=True)
        with open(IPHIST_TIMES_FILE, "w", encoding="utf-8") as f:
            json.dump(IP_TIMES, f, ensure_ascii=False, indent=2)
        _last_ip_times_save = now
        _ip_times_dirty = False
    except Exception as e:
        logger.warning("ip_times save failed: %s", e)

def _record_ip_seen(sub: str, ip: str, when: Optional[datetime.datetime]=None):
    global _ip_hist_dirty, _ip_times_dirty
    if not sub or not ip: return
    if when is None: when = datetime.datetime.now()
    day = when.strftime("%Y-%m-%d")
    s = IP_HISTORY.setdefault(sub, {}); arr = s.setdefault(day, [])
    if ip not in arr:
        arr.append(ip); _ip_hist_dirty = True
    tmap = IP_TIMES.setdefault(sub, {}).setdefault(day, {}).setdefault(ip, [])
    hhmmss = when.strftime("%H:%M:%S")
    if not tmap or tmap[-1] != hhmmss:
        tmap.append(hhmmss); _ip_times_dirty = True

CURRENT_IPS: Dict[str, Dict[str,int]] = {}
def _ip_inc(sub: str, ip: str):
    m = CURRENT_IPS.setdefault(sub, {}); m[ip] = m.get(ip, 0) + 1
def _ip_dec(sub: str, ip: str):
    m = CURRENT_IPS.get(sub);
    if not m: return
    c = m.get(ip, 0) - 1
    if c <= 0: m.pop(ip, None)
    else: m[ip] = c
def _current_ips_for(sub: str) -> List[str]:
    m = CURRENT_IPS.get(sub, {}); return sorted([ip for ip,cnt in m.items() if cnt>0])

# === 세션 로그 ===
SESSIONS_FILE = os.getenv("SESSIONS_FILE", "/opt/tunneler/ip_sessions.json")
SESSIONS: Dict[str, Dict[str, Dict[str, List[Dict[str, Optional[str]]]]]] = _load_json(SESSIONS_FILE, {})
_sessions_dirty = False
_last_sessions_save = 0.0

def _save_sessions_if_needed(force=False):
    global _sessions_dirty, _last_sessions_save
    now = time.time()
    if not force and (not _sessions_dirty or now - _last_sessions_save < 5.0): return
    try:
        os.makedirs(os.path.dirname(SESSIONS_FILE), exist_ok=True)
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(SESSIONS, f, ensure_ascii=False, indent=2)
        _last_sessions_save = now
        _sessions_dirty = False
    except Exception as e:
        logger.warning("sessions save failed: %s", e)

def _start_session(
    sub: str,
    ip: str,
    when: Optional[datetime.datetime]=None,
    proto: Optional[str]=None,
    mapping_name: Optional[str]=None,
    remote_port: int=0,
):
    global _sessions_dirty
    if not when: when = datetime.datetime.now()
    day = when.strftime("%Y-%m-%d")
    rec = {"start": when.replace(microsecond=0).isoformat(), "end": None}
    if proto:
        rec["proto"] = proto
    if mapping_name:
        rec["mapping"] = mapping_name
    if remote_port > 0:
        rec["remote_port"] = int(remote_port)
    arr = SESSIONS.setdefault(sub, {}).setdefault(day, {}).setdefault(ip, [])
    arr.append(rec); _sessions_dirty = True
    return (sub, day, ip, len(arr)-1)

def _end_session(key, when: Optional[datetime.datetime]=None):
    global _sessions_dirty
    if not key: return
    sub, day, ip, idx = key
    try:
        if not when: when = datetime.datetime.now()
        arr = SESSIONS.get(sub, {}).get(day, {}).get(ip, [])
        if 0 <= idx < len(arr) and not arr[idx].get("end"):
            arr[idx]["end"] = when.replace(microsecond=0).isoformat()
            _sessions_dirty = True
    except Exception:
        pass

# 인증(클라이언트용): 토큰 화이트리스트
TOK_FILE = os.getenv("TOK_FILE", "/opt/tunneler/tokens.txt")
def load_tokens() -> List[str]:
    if not os.path.exists(TOK_FILE): return []
    try:
        with open(TOK_FILE, "r", encoding="utf-8") as f:
            return [x.strip() for x in f.read().split(",") if x.strip()]
    except Exception:
        return []
ALLOWED_TOKENS = set(load_tokens())

# 관리자 Basic Auth
ADMIN_USER = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "")
ADMIN_SESSION_COOKIE = "tunneler_admin_session"
ADMIN_SESSION_TTL = max(300, int(os.getenv("ADMIN_SESSION_TTL_SECONDS", "43200")))

# 상태 파일
STATE_FILE = os.getenv("ADMIN_STATE_FILE", "/opt/tunneler/admin_state.json")
def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            "admin_ip_allow": [],
            "access_schedules": [],
            "bot_blocking": {"enabled": True, "block_empty_ua": True, "rules": list(DEFAULT_BOT_RULES)},
            "per_tunnel_schedules": {},
            "per_tunnel_ip_deny": {},
            "token_meta": {},
            "revoked_tokens": [],
            "tunnel_ip_deny": [],
            "per_tunnel_limits": {},
            "managed_mappings": {},
            "suppressed_client_mappings": {}
        }
    try:
        with open(STATE_FILE,"r",encoding="utf-8") as f:
            s=json.load(f)
            s.setdefault("admin_ip_allow",[])
            s.setdefault("access_schedules",[])
            s.setdefault("bot_blocking", {"enabled": True, "block_empty_ua": True, "rules": list(DEFAULT_BOT_RULES)})
            s.setdefault("per_tunnel_schedules",{})
            s.setdefault("per_tunnel_ip_deny",{})
            s.setdefault("token_meta",{})
            s.setdefault("revoked_tokens",[])
            s.setdefault("tunnel_ip_deny",[])
            s.setdefault("per_tunnel_limits",{})
            s.setdefault("managed_mappings",{})
            s.setdefault("suppressed_client_mappings",{})
            return s
    except Exception:
        return {
            "admin_ip_allow": [],
            "access_schedules": [],
            "bot_blocking": {"enabled": True, "block_empty_ua": True, "rules": list(DEFAULT_BOT_RULES)},
            "per_tunnel_schedules": {},
            "per_tunnel_ip_deny": {},
            "token_meta": {},
            "revoked_tokens": [],
            "tunnel_ip_deny": [],
            "per_tunnel_limits": {},
            "managed_mappings": {},
            "suppressed_client_mappings": {}
        }

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE,"w",encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

STATE = load_state()

def normalized_bot_blocking(raw: Optional[Dict[str, Any]]=None, fill_defaults: bool=False) -> Dict[str, Any]:
    src = raw or {}
    raw_rules = src.get("rules") if "rules" in src else None
    rules = [str(rule).strip().lower() for rule in (raw_rules or []) if str(rule).strip()]
    if fill_defaults and not rules:
        rules = list(DEFAULT_BOT_RULES)
    return {
        "enabled": bool(src.get("enabled", True)),
        "block_empty_ua": bool(src.get("block_empty_ua", True)),
        "rules": sorted(dict.fromkeys(rules)),
    }

STATE["bot_blocking"] = normalized_bot_blocking(STATE.get("bot_blocking"), fill_defaults=True)

# 포트 범위
PORT_RANGE_TCP = os.getenv("TCP_PORT_RANGE","20000-20100")
PORT_RANGE_UDP = os.getenv("UDP_PORT_RANGE","21000-21100")
TCP_START, TCP_END = [int(x) for x in PORT_RANGE_TCP.split("-")]
UDP_START, UDP_END = [int(x) for x in PORT_RANGE_UDP.split("-")]
INUSE_TCP, INUSE_UDP = set(), set()

HOP_BY_HOP_HEADERS = {
    "connection","keep-alive","proxy-authenticate","proxy-authorization",
    "te","trailers","transfer-encoding","upgrade"
}

# 최근 로그(대시보드 실시간)
LOG_RING = deque(maxlen=500)
MAX_LOG_LINES = 500
def ring_log(line: str):
    if len(LOG_RING) >= MAX_LOG_LINES:
        with contextlib.suppress(Exception):
            LOG_RING.popleft()
    LOG_RING.append(line)
    logger.info(line)

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: Optional[str]) -> bytes: return base64.b64decode((s or "").encode("ascii")) if s else b""

def extract_subdomain(host: str) -> Optional[str]:
    host = host.split(":")[0]; parts = host.split(".")
    return parts[0] if len(parts) >= 3 else None

def _normalized_ip(value: str) -> Optional[str]:
    raw = (value or "").strip().strip('"').strip("'")
    if not raw or raw.lower() == "unknown":
        return None
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    elif raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return None

def peer_ip(request: web.Request) -> str:
    peer = None
    transport = getattr(request, "transport", None)
    if transport is not None:
        peername = transport.get_extra_info("peername")
        if isinstance(peername, tuple) and peername:
            peer = peername[0]
        elif isinstance(peername, str):
            peer = peername
    return _normalized_ip(str(peer or request.remote or "")) or "127.0.0.1"

def forwarded_ip(request: web.Request) -> Optional[str]:
    header_order = [
        "CF-Connecting-IP",
        "True-Client-IP",
        "Fastly-Client-IP",
        "X-Forwarded-For",
        "X-Original-Forwarded-For",
        "X-Real-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "X-ProxyUser-IP",
        "Fly-Client-IP",
    ]
    for header in header_order:
        raw = request.headers.get(header, "")
        if not raw:
            continue
        for part in raw.split(","):
            ip = _normalized_ip(part)
            if ip:
                return ip
    forwarded = request.headers.get("Forwarded", "")
    for entry in forwarded.split(","):
        for part in entry.split(";"):
            seg = part.strip()
            if not seg.lower().startswith("for="):
                continue
            ip = _normalized_ip(seg.split("=", 1)[1])
            if ip:
                return ip
    return None

def client_ip(request: web.Request) -> str:
    return forwarded_ip(request) or peer_ip(request)

def request_ip_label(request: web.Request) -> str:
    real = client_ip(request)
    peer = peer_ip(request)
    if real != peer:
        return f"{real} via {peer}"
    return real

LOG_META_CACHE: Dict[str, Any] = {"stamp": 0.0, "items": []}

def _log_modified_at(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).replace(microsecond=0).isoformat()

def list_log_files(force: bool=False) -> List[Dict[str, Any]]:
    now = time.time()
    if not force and now - float(LOG_META_CACHE.get("stamp", 0.0)) < 2.0:
        return list(LOG_META_CACHE.get("items", []))

    items: List[Dict[str, Any]] = []
    try:
        with os.scandir(LOG_DIR) as entries:
            for entry in entries:
                if not entry.name.startswith("server.log") or not entry.is_file():
                    continue
                stat = entry.stat()
                items.append({
                    "name": entry.name,
                    "size": int(stat.st_size),
                    "mtime": float(stat.st_mtime),
                    "modified_at": _log_modified_at(stat.st_mtime),
                })
    except FileNotFoundError:
        items = []
    items.sort(key=lambda item: (item["mtime"], item["name"]), reverse=True)
    LOG_META_CACHE["stamp"] = now
    LOG_META_CACHE["items"] = items
    return list(items)

def read_log_tail(path: str, max_lines: int=800, max_bytes: int=262144) -> Tuple[str, bool]:
    max_lines = max(50, min(5000, int(max_lines or 800)))
    max_bytes = max(32 * 1024, min(2 * 1024 * 1024, int(max_bytes or 262144)))
    chunk_size = 8192
    data = b""
    pos = 0
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        remaining = pos
        while remaining > 0 and len(data) < max_bytes and data.count(b"\n") <= max_lines:
            read_size = min(chunk_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            data = f.read(read_size) + data
        pos = remaining
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    truncated = pos > 0 or len(lines) > max_lines
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(lines), truncated

# === 대시보드 접속 허용 IP ===
def ip_allowed(ip: str) -> bool:
    allow = STATE.get("admin_ip_allow", [])
    if not allow: return True
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for rule in allow:
        try:
            if "/" in rule:
                if ip_obj in ipaddress.ip_network(rule, strict=False): return True
            else:
                if ip == rule: return True
        except Exception:
            continue
    return False

def request_blocked_as_bot(request: web.Request) -> bool:
    cfg = normalized_bot_blocking(STATE.get("bot_blocking"))
    if not cfg.get("enabled"):
        return False
    ua = (request.headers.get("User-Agent") or "").strip().lower()
    if not ua:
        return bool(cfg.get("block_empty_ua", True))
    return any(rule in ua for rule in cfg.get("rules", []))

def _prune_bot_state():
    now = time.time()
    expired = [ip for ip, meta in BOT_IP_FLAGS.items() if float(meta.get("expires_at", 0.0)) <= now]
    for ip in expired:
        BOT_IP_FLAGS.pop(ip, None)
    stale = []
    for ip, entries in BOT_ACCESS_RECENT.items():
        while entries and now - entries[0][0] > 30.0:
            entries.popleft()
        if not entries:
            stale.append(ip)
    for ip in stale:
        BOT_ACCESS_RECENT.pop(ip, None)

def flag_bot_ip(ip: str, reason: str, ttl: float=86400.0):
    if not ip:
        return
    BOT_IP_FLAGS[ip] = {"reason": reason, "expires_at": time.time() + ttl}

def bot_ip_blocked(ip: str) -> bool:
    _prune_bot_state()
    return ip in BOT_IP_FLAGS

def register_bot_signature(ip: str, signature: str) -> bool:
    if not ip or not signature:
        return False
    _prune_bot_state()
    entries = BOT_ACCESS_RECENT.setdefault(ip, deque())
    entries.append((time.time(), signature))
    unique_signatures = {sig for _, sig in entries}
    if len(unique_signatures) >= 6:
        flag_bot_ip(ip, f"scan:{len(unique_signatures)}")
        return True
    return False

def protocol_blocked_as_bot(ip: str, signature: str, user_agent: str="") -> bool:
    cfg = normalized_bot_blocking(STATE.get("bot_blocking"))
    if not cfg.get("enabled"):
        return False
    if bot_ip_blocked(ip):
        return True
    ua = (user_agent or "").strip().lower()
    if ua:
        for rule in cfg.get("rules", []):
            if rule and rule in ua:
                flag_bot_ip(ip, f"ua:{rule}")
                return True
    elif user_agent == "":
        # HTTP only. Non-HTTP callers should pass a non-empty sentinel if empty user-agent shouldn't apply.
        if cfg.get("block_empty_ua"):
            flag_bot_ip(ip, "empty-user-agent")
            return True
    if register_bot_signature(ip, signature):
        return True
    return False

# === 터널 접근 차단 IP ===
def tunnel_ip_rules(sub: Optional[str]=None) -> List[str]:
    rules = list(STATE.get("tunnel_ip_deny", []) or [])
    if sub:
        rules.extend(((STATE.get("per_tunnel_ip_deny") or {}).get(sub, []) or []))
    return rules

def tunnel_ip_blocked(ip: str, sub: Optional[str]=None) -> bool:
    deny = tunnel_ip_rules(sub)
    if not deny: return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for rule in deny:
        try:
            if "/" in rule:
                if ip_obj in ipaddress.ip_network(rule, strict=False): return True
            else:
                if ip == rule: return True
        except Exception:
            continue
    return False

# ===== 접속 허용 시간대 =====
def _parse_days(spec: str) -> set:
    spec = (spec or "all").lower().strip()
    mapd = {"mon":0,"tue":1,"wed":2,"thu":3,"fri":4,"sat":5,"sun":6}
    if spec == "all": return set(range(7))
    if spec == "mon-fri": return set(range(5))
    if spec == "sat-sun": return {5,6}
    days=set()
    for part in spec.split(","):
        p=part.strip()[:3]
        if p in mapd: days.add(mapd[p])
    return days or set(range(7))

def _time_in_ranges(rules, now=None) -> bool:
    if not rules: return True
    if now is None: now = datetime.datetime.now()
    wd = now.weekday()
    cur = now.hour*60 + now.minute
    for sch in rules:
        days = _parse_days(sch.get("days","all"))
        st = sch.get("start","00:00"); en = sch.get("end","23:59")
        try:
            sh,sm = [int(x) for x in st.split(":")]
            eh,em = [int(x) for x in en.split(":")]
        except Exception:
            continue
        smin = sh*60+sm; emin = eh*60+em
        if wd in days:
            if smin <= emin:
                if smin <= cur <= emin: return True
            else:
                if cur >= smin or cur <= emin: return True
    return False

def access_allowed_for(sub: Optional[str]) -> bool:
    rules = []
    if sub:
        rules = (STATE.get("per_tunnel_schedules") or {}).get(sub, [])
    if not rules:
        rules = STATE.get("access_schedules", [])
    return _time_in_ranges(rules)

# ===== 토큰 메타 =====
def touch_token_meta(token: str, ip: str):
    if not token: return
    meta = STATE.setdefault("token_meta", {})
    meta[token] = {
        "last_ip": ip,
        "last_at": datetime.datetime.now().replace(microsecond=0).isoformat()
    }
    save_state(STATE)

# ===== 대역폭 제한 =====
def _current_usage_of(sub: str):
    day, week, month = _date_keys()
    d = USAGE.get(sub, {})
    daily = (d.get("daily", {}).get(day) or {"tx":0,"rx":0})
    weekly= (d.get("weekly",{}).get(week) or {"tx":0,"rx":0})
    monthly=(d.get("monthly",{}).get(month) or {"tx":0,"rx":0})
    return {"daily": daily["tx"]+daily["rx"], "weekly": weekly["tx"]+weekly["rx"], "monthly": monthly["tx"]+monthly["rx"]}

def allowed_by_limit(sub: str) -> bool:
    limits = (STATE.get("per_tunnel_limits") or {}).get(sub, {})
    if not limits: return True
    cur = _current_usage_of(sub)
    for k in ("daily","weekly","monthly"):
        lim = max(0, int(limits.get(k, 0) or 0))
        if lim and cur.get(k,0) >= lim:
            return False
    return True

def verify_auth(auth_token: str) -> Tuple[bool, str]:
    revoked = set(STATE.get("revoked_tokens", []) or [])
    if auth_token and auth_token in revoked:
        return False, "token_revoked"
    if ALLOWED_TOKENS:
        if auth_token in ALLOWED_TOKENS:
            return True, "ok"
        return False, "unauthorized"
    return True, "ok"

def broadcast(event: dict):
    dead = []
    payload = json.dumps(event)
    for ws in ADMIN_WSS:
        try:
            asyncio.create_task(ws.send_str(payload))
        except Exception:
            dead.append(ws)
    for ws in dead:
        with contextlib.suppress(ValueError):
            ADMIN_WSS.remove(ws)

def parse_basic_auth(request: web.Request) -> bool:
    if not ADMIN_USER or not ADMIN_PASS: return False
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Basic "): return False
    try:
        raw = base64.b64decode(auth.split(" ",1)[1].encode("ascii")).decode("utf-8")
        user, pw = raw.split(":",1)
    except Exception:
        return False
    return (user == ADMIN_USER and pw == ADMIN_PASS)

def _prune_admin_sessions():
    now = time.time()
    expired = [token for token, expires_at in ADMIN_SESSIONS.items() if expires_at <= now]
    for token in expired:
        ADMIN_SESSIONS.pop(token, None)

def create_admin_session() -> str:
    _prune_admin_sessions()
    token = uuid.uuid4().hex
    ADMIN_SESSIONS[token] = time.time() + ADMIN_SESSION_TTL
    return token

def admin_session_valid(request: web.Request) -> bool:
    _prune_admin_sessions()
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if not token:
        return False
    expires_at = ADMIN_SESSIONS.get(token)
    if not expires_at:
        return False
    if expires_at <= time.time():
        ADMIN_SESSIONS.pop(token, None)
        return False
    ADMIN_SESSIONS[token] = time.time() + ADMIN_SESSION_TTL
    return True

def admin_authenticated(request: web.Request) -> bool:
    return admin_session_valid(request) or parse_basic_auth(request)

def require_admin(handler):
    async def wrapper(request: web.Request):
        ip = client_ip(request)
        if not ip_allowed(ip):
            return web.Response(status=403, text="Forbidden by IP allowlist")
        if admin_authenticated(request):
            resp = await handler(request)
            return resp
        if request.path.startswith("/api/") or request.path == "/admin_ws":
            return web.json_response({"ok":False, "reason":"unauthorized"}, status=401)
        raise web.HTTPFound("/login")
    return wrapper

# ===== 포트 할당 =====
async def alloc_port(start: int, end: int, inuse: set, type_=socket.SOCK_STREAM) -> Optional[int]:
    for p in range(start, end+1):
        if p in inuse: continue
        with closing(socket.socket(socket.AF_INET, type_)) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: s.bind(("0.0.0.0", p))
            except OSError: continue
        return p
    return None

async def choose_port(requested: int, start: int, end: int, inuse: set, type_: int) -> Optional[int]:
    req = max(0, int(requested or 0))
    if req:
        if req in inuse:
            return None
        with closing(socket.socket(socket.AF_INET, type_)) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", req))
            except OSError:
                return None
        return req
    return await alloc_port(start, end, inuse, type_)

def managed_mapping_bucket(sub: str) -> Dict[str, Dict[str, Dict[str, Any]]]:
    store = STATE.setdefault("managed_mappings", {})
    bucket = store.setdefault(sub, {})
    bucket.setdefault("tcp", {})
    bucket.setdefault("udp", {})
    return bucket

def suppressed_mapping_bucket(sub: str) -> Dict[str, List[str]]:
    store = STATE.setdefault("suppressed_client_mappings", {})
    bucket = store.setdefault(sub, {})
    bucket.setdefault("tcp", [])
    bucket.setdefault("udp", [])
    return bucket

def mapping_suppressed(sub: str, proto: str, name: str) -> bool:
    return name in (suppressed_mapping_bucket(sub).get(proto, []) or [])

def suppress_mapping(sub: str, proto: str, name: str):
    bucket = suppressed_mapping_bucket(sub)
    names = [item for item in bucket.get(proto, []) if item != name]
    names.append(name)
    bucket[proto] = sorted(dict.fromkeys(names))

def unsuppress_mapping(sub: str, proto: str, name: str):
    bucket = suppressed_mapping_bucket(sub)
    bucket[proto] = [item for item in (bucket.get(proto, []) or []) if item != name]

def iter_managed_configs(sub: str, proto: str) -> List[Dict[str, Any]]:
    bucket = managed_mapping_bucket(sub).get(proto, {})
    items: List[Dict[str, Any]] = []
    for name, cfg in bucket.items():
        host = (cfg or {}).get("host")
        port = int((cfg or {}).get("port") or 0)
        if not name or not host or port <= 0:
            continue
        items.append({
            "name": name,
            "host": host,
            "port": port,
            "remote_port": int((cfg or {}).get("remote_port") or 0),
        })
    items.sort(key=lambda item: item["name"])
    return items

async def close_tcp_stream(sub: str, sid: str, stream: Dict[str, Any], ws: Optional[web.WebSocketResponse]=None, notify_client: bool=False):
    rip = stream.get("rip", "")
    if rip:
        _ip_dec(sub, rip)
    sess_key = stream.get("sess_key")
    if sess_key:
        _end_session(sess_key)
    writer: Optional[asyncio.StreamWriter] = stream.get("writer")
    if writer:
        with contextlib.suppress(Exception):
            writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    if notify_client and ws and not ws.closed:
        with contextlib.suppress(Exception):
            await ws.send_json({"type":"tcp_close","stream_id":sid,"who":"server"})

async def close_udp_flow(sub: str, flow_meta: Dict[str, Any], ws: Optional[web.WebSocketResponse]=None, notify_client: bool=False):
    rip = flow_meta.get("rip", "")
    if rip:
        _ip_dec(sub, rip)
    sess_key = flow_meta.get("sess_key")
    if sess_key:
        _end_session(sess_key)
    if notify_client and ws and not ws.closed:
        with contextlib.suppress(Exception):
            await ws.send_json({"type":"udp_close","flow_id":flow_meta.get("flow_id"),"who":"server"})

async def disconnect_ip(sub: str, ip: str) -> int:
    info = TUNNELS.get(sub)
    if not info:
        return 0
    ws = info.get("ws")
    closed = 0
    for tcp in info.get("tcp", {}).values():
        for sid, stream in list(tcp.get("streams", {}).items()):
            if stream.get("rip") != ip:
                continue
            tcp["streams"].pop(sid, None)
            await close_tcp_stream(sub, sid, stream, ws=ws, notify_client=True)
            closed += 1
    for udp in info.get("udp", {}).values():
        for addr, flow_meta in list(udp.get("flows", {}).items()):
            if flow_meta.get("rip") != ip:
                continue
            udp["flows"].pop(addr, None)
            await close_udp_flow(sub, flow_meta, ws=ws, notify_client=True)
            closed += 1
    return closed

async def disconnect_blocked_ips(sub: Optional[str]=None):
    targets = [sub] if sub else list(TUNNELS.keys())
    for tunnel_sub in targets:
        for ip in list(_current_ips_for(tunnel_sub)):
            if tunnel_ip_blocked(ip, tunnel_sub):
                await disconnect_ip(tunnel_sub, ip)

async def remove_runtime_mapping(sub: str, proto: str, name: str):
    info = TUNNELS.get(sub)
    if not info:
        return
    ws = info.get("ws")
    if proto == "tcp":
        mapping = info.get("tcp", {}).pop(name, None)
        if not mapping:
            return
        mapping["server"].close()
        with contextlib.suppress(Exception):
            await mapping["server"].wait_closed()
        INUSE_TCP.discard(mapping["port"])
        for sid, stream in list(mapping.get("streams", {}).items()):
            await close_tcp_stream(sub, sid, stream, ws=ws, notify_client=True)
    else:
        mapping = info.get("udp", {}).pop(name, None)
        if not mapping:
            return
        mapping["transport"].close()
        INUSE_UDP.discard(mapping["port"])
        for _, flow_meta in list(mapping.get("flows", {}).items()):
            await close_udp_flow(sub, flow_meta, ws=ws, notify_client=True)

async def send_control_and_wait(sub: str, action: str, payload: Optional[Dict[str, Any]]=None, timeout: float=8.0) -> Tuple[bool, str]:
    info = TUNNELS.get(sub)
    if not info:
        return False, "tunnel_offline"
    ws = info.get("ws")
    if not ws or ws.closed:
        return False, "tunnel_offline"
    req_id = uuid.uuid4().hex
    fut = asyncio.get_running_loop().create_future()
    CONTROL_PENDING[req_id] = fut
    message = {"type":"control", "id":req_id, "action":action}
    if payload:
        message.update(payload)
    try:
        await ws.send_json(message)
    except Exception:
        CONTROL_PENDING.pop(req_id, None)
        return False, "send_failed"
    try:
        result = await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        CONTROL_PENDING.pop(req_id, None)
        return False, "timeout"
    except Exception:
        CONTROL_PENDING.pop(req_id, None)
        return False, "control_failed"
    finally:
        CONTROL_PENDING.pop(req_id, None)
    return bool(result.get("ok")), str(result.get("reason") or "")

def broadcast_refresh():
    broadcast({"kind":"refresh"})

async def attach_tcp_mapping(subdomain: str, ws: web.WebSocketResponse, name: str, requested_port: int=0, managed: bool=False) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if name in TUNNELS[subdomain]["tcp"]:
        return None, "duplicate_name"
    port = await choose_port(requested_port, TCP_START, TCP_END, INUSE_TCP, socket.SOCK_STREAM)
    if not port:
        return None, "port_unavailable"

    async def _tcp_handler(reader, writer, _name=name, _sub=subdomain):
        pinfo = writer.get_extra_info("peername")
        rip = (pinfo[0] if pinfo else "") or "0.0.0.0"
        if protocol_blocked_as_bot(rip, f"tcp:{_sub}:{_name}", user_agent="-"):
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            return
        if tunnel_ip_blocked(rip, _sub) or not access_allowed_for(_sub) or not allowed_by_limit(_sub):
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            return
        sid = str(uuid.uuid4())
        sess_key = _start_session(_sub, rip, proto="tcp", mapping_name=_name, remote_port=port)
        TUNNELS[_sub]["tcp"][_name]["streams"][sid] = {"reader":reader,"writer":writer,"rip":rip,"sess_key":sess_key}
        _ip_inc(_sub, rip)
        _record_ip_seen(_sub, rip)

        sock = writer.get_extra_info("socket")
        if sock is not None:
            import socket as pysock
            with contextlib.suppress(Exception):
                sock.setsockopt(pysock.IPPROTO_TCP, pysock.TCP_NODELAY, 1)
        await ws.send_json({"type":"tcp_open","name":_name,"stream_id":sid})
        ring_log(f"TCP OPEN {_sub}/{_name}/{sid} from {rip}")

        async def pump_up():
            try:
                while True:
                    if not access_allowed_for(_sub) or not allowed_by_limit(_sub):
                        break
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    _bw_acc(_sub, "rx", len(chunk))
                    _add_usage(_sub, tx=0, rx=len(chunk))
                    await ws.send_json({"type":"tcp_data","stream_id":sid,"b64":b64e(chunk)})
            except Exception:
                pass
            finally:
                with contextlib.suppress(Exception):
                    await ws.send_json({"type":"tcp_close","stream_id":sid,"who":"server"})
        asyncio.create_task(pump_up())

    try:
        server_obj = await asyncio.start_server(_tcp_handler, "0.0.0.0", port)
    except OSError:
        return None, "port_unavailable"
    INUSE_TCP.add(port)
    TUNNELS[subdomain]["tcp"][name] = {"port":port,"server":server_obj,"streams":{}, "managed":managed}
    return {"name":name, "remote_port":port}, None

async def attach_udp_mapping(subdomain: str, ws: web.WebSocketResponse, name: str, requested_port: int=0, managed: bool=False) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if name in TUNNELS[subdomain]["udp"]:
        return None, "duplicate_name"
    port = await choose_port(requested_port, UDP_START, UDP_END, INUSE_UDP, socket.SOCK_DGRAM)
    if not port:
        return None, "port_unavailable"

    loop = asyncio.get_running_loop()
    flows: Dict[Any, Dict[str, Any]] = {}
    flow_idle = 30.0

    class UdpProto(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            rip = addr[0] if addr else "0.0.0.0"
            if protocol_blocked_as_bot(rip, f"udp:{subdomain}:{name}", user_agent="-"):
                return
            if tunnel_ip_blocked(rip, subdomain) or not access_allowed_for(subdomain) or not allowed_by_limit(subdomain):
                return
            if addr not in flows:
                fid = str(uuid.uuid4())
                sess_key = _start_session(subdomain, rip, proto="udp", mapping_name=name, remote_port=port)
                flows[addr] = {"flow_id":fid,"last":loop.time(),"rip":rip,"sess_key":sess_key}
                _ip_inc(subdomain, rip)
                _record_ip_seen(subdomain, rip)
                asyncio.create_task(ws.send_json({"type":"udp_open","name":name,"flow_id":fid}))
            flows[addr]["last"] = loop.time()
            fid = flows[addr]["flow_id"]
            _bw_acc(subdomain, "rx", len(data))
            _add_usage(subdomain, tx=0, rx=len(data))
            asyncio.create_task(ws.send_json({"type":"udp_data","flow_id":fid,"b64":b64e(data)}))

    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: UdpProto(), local_addr=("0.0.0.0", port))
    except OSError:
        return None, "port_unavailable"
    INUSE_UDP.add(port)

    async def gc():
        while True:
            await asyncio.sleep(5)
            if subdomain not in TUNNELS or name not in TUNNELS.get(subdomain, {}).get("udp", {}):
                break
            now = loop.time()
            for addr, flow_meta in list(flows.items()):
                if now - flow_meta["last"] <= flow_idle:
                    continue
                flows.pop(addr, None)
                await close_udp_flow(subdomain, flow_meta, ws=ws, notify_client=True)

    asyncio.create_task(gc())
    TUNNELS[subdomain]["udp"][name] = {"port":port,"transport":transport,"flows":flows, "managed":managed}
    return {"name":name, "remote_port":port}, None

# ===== WS 핸들러 (클라이언트) =====
async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=20.0)
    await ws.prepare(request)
    peer = client_ip(request)
    peer_label = request_ip_label(request)
    logger.info("WS connected from %s", peer_label); ring_log(f"WS connected: {peer_label}")

    subdomain: Optional[str] = None
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try: data = json.loads(msg.data)
                except json.JSONDecodeError:
                    await ws.close(message=b"invalid json"); break

                mtype = data.get("type")

                # ----- 등록 -----
                if mtype == "register":
                    candidate = data.get("subdomain")
                    auth_token = data.get("auth_token","")
                    tcp_cfgs = [
                        cfg for cfg in (data.get("tcp_configs",[]) or [])
                        if cfg.get("name") and not mapping_suppressed(candidate or "", "tcp", cfg.get("name"))
                    ]
                    udp_cfgs = [
                        cfg for cfg in (data.get("udp_configs",[]) or [])
                        if cfg.get("name") and not mapping_suppressed(candidate or "", "udp", cfg.get("name"))
                    ]
                    managed_tcp_cfgs = []
                    managed_udp_cfgs = []

                    if not candidate or not candidate.isalnum():
                        await ws.send_json({"type":"register_result","ok":False,"reason":"bad_subdomain"}); continue
                    managed_tcp_cfgs = iter_managed_configs(candidate, "tcp")
                    managed_udp_cfgs = iter_managed_configs(candidate, "udp")

                    if not access_allowed_for(candidate):
                        await ws.send_json({"type":"register_result","ok":False,"reason":"time_forbidden"}); continue
                    if not allowed_by_limit(candidate):
                        await ws.send_json({"type":"register_result","ok":False,"reason":"quota_exceeded"}); continue

                    ok, reason = verify_auth(auth_token)
                    if not ok:
                        await ws.send_json({"type":"register_result","ok":False,"reason":reason}); continue

                    touch_token_meta(auth_token, peer or "")

                    if candidate in TUNNELS:
                        with contextlib.suppress(Exception):
                            await TUNNELS[candidate]["ws"].close(message=b"replaced")

                    subdomain = candidate
                    TUNNELS[subdomain] = {
                        "ws": ws,
                        "tcp": {},
                        "udp": {},
                        "connected_at": datetime.datetime.now().replace(microsecond=0).isoformat(),
                        "peer_ip": peer,
                        "auth_token": auth_token,
                    }
                    ring_log(f"REGISTER {subdomain} by {peer}")
                    broadcast({"kind":"register","subdomain":subdomain})

                    tcp_assigned = []
                    seen_tcp = set()
                    for cfg, is_managed in ([(cfg, False) for cfg in tcp_cfgs] + [(cfg, True) for cfg in managed_tcp_cfgs]):
                        name = cfg.get("name")
                        if not name or not name.isidentifier() or name in seen_tcp:
                            continue
                        seen_tcp.add(name)
                        assigned, _ = await attach_tcp_mapping(
                            subdomain,
                            ws,
                            name,
                            requested_port=int(cfg.get("remote_port", 0) or 0),
                            managed=is_managed,
                        )
                        if assigned:
                            tcp_assigned.append(assigned)

                    udp_assigned = []
                    seen_udp = set()
                    for cfg, is_managed in ([(cfg, False) for cfg in udp_cfgs] + [(cfg, True) for cfg in managed_udp_cfgs]):
                        name = cfg.get("name")
                        if not name or not name.isidentifier() or name in seen_udp:
                            continue
                        seen_udp.add(name)
                        assigned, _ = await attach_udp_mapping(
                            subdomain,
                            ws,
                            name,
                            requested_port=int(cfg.get("remote_port", 0) or 0),
                            managed=is_managed,
                        )
                        if assigned:
                            udp_assigned.append(assigned)

                    await ws.send_json({
                        "type":"register_result",
                        "ok":True,
                        "tcp_assigned":tcp_assigned,
                        "udp_assigned":udp_assigned,
                        "managed_tcp_configs":managed_tcp_cfgs,
                        "managed_udp_configs":managed_udp_cfgs,
                    })
                    ring_log(f"ASSIGNED {subdomain} TCP={tcp_assigned} UDP={udp_assigned}")
                    broadcast({"kind":"assigned","subdomain":subdomain,"tcp":tcp_assigned,"udp":udp_assigned})

                elif mtype == "tcp_data":
                    sid=data["stream_id"]; payload=b64d(data.get("b64"))
                    if subdomain:
                        for t in TUNNELS[subdomain]["tcp"].values():
                            st=t["streams"].get(sid)
                            if st:
                                try:
                                    if access_allowed_for(subdomain) and allowed_by_limit(subdomain):
                                        _bw_acc(subdomain, "tx", len(payload)); _add_usage(subdomain, tx=len(payload), rx=0)
                                        st["writer"].write(payload); await st["writer"].drain()
                                except Exception: pass
                                break

                elif mtype == "tcp_close":
                    sid=data["stream_id"]
                    if subdomain:
                        for t in TUNNELS[subdomain]["tcp"].values():
                            st=t["streams"].pop(sid, None)
                            if st:
                                await close_tcp_stream(subdomain, sid, st)
                                break

                elif mtype == "udp_data":
                    fid=data["flow_id"]; payload=b64d(data.get("b64"))
                    if subdomain:
                        for ud in TUNNELS[subdomain]["udp"].values():
                            for addr,meta in ud["flows"].items():
                                if meta["flow_id"]==fid:
                                    if access_allowed_for(subdomain) and allowed_by_limit(subdomain):
                                        _bw_acc(subdomain, "tx", len(payload)); _add_usage(subdomain, tx=len(payload), rx=0)
                                        ud["transport"].sendto(payload, addr)
                                        meta["last"]=asyncio.get_running_loop().time()
                                    break

                elif mtype == "udp_close":
                    fid=data["flow_id"]
                    if subdomain:
                        for ud in TUNNELS[subdomain]["udp"].values():
                            for addr,meta in list(ud["flows"].items()):
                                if meta["flow_id"]==fid:
                                    ud["flows"].pop(addr,None)
                                    await close_udp_flow(subdomain, meta)
                                    break

                elif mtype == "control_ack":
                    req_id = data.get("id")
                    fut = CONTROL_PENDING.get(req_id)
                    if fut and not fut.done():
                        fut.set_result(data)

                elif mtype == "proxy_response":
                    rid=data.get("id")
                    fut=PENDING.pop(rid, None)
                    if fut and not fut.done(): fut.set_result(data)

            elif msg.type == WSMsgType.ERROR:
                logger.warning("WS error: %s", ws.exception()); ring_log(f"WS error: {ws.exception()}")

    finally:
        for sub, info in list(TUNNELS.items()):
            if info.get("ws") is ws:
                for t in info.get("tcp",{}).values():
                    with contextlib.suppress(Exception):
                        t["server"].close()
                    INUSE_TCP.discard(t["port"])
                    for sid, st in list(t.get("streams",{}).items()):
                        with contextlib.suppress(Exception):
                            await close_tcp_stream(sub, sid, st)
                for u in info.get("udp",{}).values():
                    with contextlib.suppress(Exception):
                        u["transport"].close()
                    INUSE_UDP.discard(u["port"])
                    for meta in list(u.get("flows",{}).values()):
                        with contextlib.suppress(Exception):
                            await close_udp_flow(sub, meta)
                TUNNELS.pop(sub, None)
                ring_log(f"UNREGISTER {sub}")
                broadcast({"kind":"unregister","subdomain":sub})
                break
    return ws

# 공개 HTTP 프록시 + /_health
async def public_http_handler(request: web.Request) -> web.StreamResponse:
    if request.path == "/_health":
        token = (request.rel_url.query.get("token") or "").strip()
        if not token:
            return web.json_response({"ok": False, "reason": "token_required"}, status=401)
        allowed, reason = verify_auth(token)
        if not allowed:
            return web.json_response({"ok": False, "reason": reason or "unauthorized"}, status=403)
        return web.json_response({
            "ok": True,
            "token": token,
            "tunnels": {
                k:{
                    "tcp":{n:v["port"] for n,v in TUNNELS[k].get("tcp",{}).items()},
                    "udp":{n:v["port"] for n,v in TUNNELS[k].get("udp",{}).items()},
                }
                for k, info in TUNNELS.items()
                if info.get("auth_token") == token
            }
        })

    ip = client_ip(request)
    if protocol_blocked_as_bot(
        ip,
        f"http:{request.headers.get('Host','')}:{request.path.split('/', 2)[1] if '/' in request.path else request.path}",
        user_agent=request.headers.get("User-Agent", ""),
    ):
        ring_log(f"BOT BLOCK {ip} {request.method} {request.path} UA={request.headers.get('User-Agent','')[:160]}")
        return web.Response(status=403, text="bot blocked")
    host = request.headers.get("Host","")
    sub = extract_subdomain(host) or request.rel_url.query.get("x-subdomain")
    if not sub or sub not in TUNNELS:
        return web.Response(status=404, text="No tunnel for this host")
    if tunnel_ip_blocked(ip, sub) or not access_allowed_for(sub):
        return web.Response(status=403, text="forbidden")
    if not allowed_by_limit(sub):
        return web.Response(status=429, text="quota exceeded")

    _record_ip_seen(sub, ip)

    ws: web.WebSocketResponse = TUNNELS[sub]["ws"]
    rid=str(uuid.uuid4())
    body=await request.read()
    if body:
        _bw_acc(sub, "rx", len(body)); _add_usage(sub, tx=0, rx=len(body))
    headers_list=[]
    for k,v in request.headers.items():
        if k.lower() in HOP_BY_HOP_HEADERS: continue
        headers_list.append([k,v])

    msg={"type":"proxy_request","id":rid,"request":{
        "method":request.method,
        "path_qs":request.rel_url.raw_path_qs,
        "headers":headers_list,
        "body_b64":b64e(body),
    }}
    fut=asyncio.get_event_loop().create_future()
    PENDING[rid]=fut
    try: await ws.send_str(json.dumps(msg))
    except Exception:
        PENDING.pop(rid,None); return web.Response(status=502, text="Tunnel not available")

    try:
        resp: Dict[str,Any] = await asyncio.wait_for(fut, timeout=float(os.getenv("REQUEST_TIMEOUT","30")))
    except asyncio.TimeoutError:
        PENDING.pop(rid,None); return web.Response(status=504, text="Upstream timeout")

    status=int(resp.get("status",502))
    resp_headers=[(k,v) for k,v in resp.get("headers",[]) if k.lower() not in HOP_BY_HOP_HEADERS]
    body_bytes=b64d(resp.get("body_b64",""))
    if body_bytes:
        _bw_acc(sub, "rx", len(body_bytes)); _add_usage(sub, tx=0, rx=len(body_bytes))
    r=web.Response(status=status, body=body_bytes)
    for k,v in resp_headers:
        if k.lower() in ["host","content-length"]: continue
        r.headers[k]=v
    return r

# ===== 관리자 대시보드 (HTML + WS) =====
LOGIN_HTML = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Tunneler Login</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
:root{
  --bg:#102019;
  --panel:#fffdf8;
  --ink:#16231d;
  --muted:#67756d;
  --line:#d2dacd;
  --brand:#1f6b47;
  --danger:#b04034;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{
  font-family:"IBM Plex Sans","Noto Sans KR",sans-serif;
  display:grid;place-items:center;padding:24px;color:#ecf6ef;
  background:
    radial-gradient(circle at top left, rgba(184,124,35,.18), transparent 22%),
    radial-gradient(circle at bottom right, rgba(31,107,71,.22), transparent 28%),
    linear-gradient(135deg, #0f1914 0%, #183126 48%, #102019 100%);
}
.shell{width:min(1120px,100%);display:grid;grid-template-columns:1.15fr .85fr;border-radius:34px;overflow:hidden;box-shadow:0 38px 90px rgba(0,0,0,.35)}
.hero{padding:42px 38px;background:linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));display:flex;flex-direction:column;justify-content:space-between}
.hero .eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:#b7c8be}
.hero h1{margin:18px 0 14px;font-size:44px;line-height:1.02;letter-spacing:-.05em}
.hero p{margin:0;color:#d4e3d7;line-height:1.7;max-width:540px}
.hero-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:30px}
.hero-card{padding:16px 18px;border-radius:22px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}
.hero-card .label{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:#b7c8be}
.hero-card .value{margin-top:8px;font-size:20px;font-weight:600}
.panel{background:var(--panel);color:var(--ink);padding:40px 34px;display:flex;flex-direction:column;justify-content:center}
.panel form{display:flex;flex-direction:column}
.panel h2{margin:0 0 10px;font-size:30px;letter-spacing:-.04em}
.panel p{margin:0 0 26px;color:var(--muted);line-height:1.6}
.field{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
.field label{font-size:13px;color:var(--muted);font-weight:600}
.field input{
  width:100%;border:1px solid var(--line);border-radius:16px;padding:14px 15px;background:#fffdfa;color:var(--ink);
}
.submit{
  margin-top:8px;margin-left:auto;display:block;border:none;border-radius:18px;background:var(--brand);color:#f0fbf4;padding:14px 16px;
  font-weight:700;font-size:15px;cursor:pointer;box-shadow:0 16px 30px rgba(31,107,71,.18)
}
.error{min-height:22px;margin-top:14px;color:var(--danger);font-size:14px}
.footer{margin-top:24px;font-size:12px;color:var(--muted)}
@media (max-width: 920px){
  .shell{grid-template-columns:1fr}
  .hero{padding:30px}
  .hero h1{font-size:34px}
  .panel{padding:28px 24px}
}
</style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div>
        <h1>Tunneler Server Admin Dashboard</h1>
      </div>
    </section>
    <section class="panel">
      <h2>관리자 로그인</h2>
      <p>설치 시 설정한 관리자 계정으로 로그인합니다.</p>
      <form id="loginForm">
        <div class="field">
          <label for="username">관리자 ID</label>
          <input id="username" name="username" autocomplete="username" required/>
        </div>
        <div class="field">
          <label for="password">비밀번호</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required/>
        </div>
        <button class="submit" type="submit">대시보드 열기</button>
        <div class="error" id="loginError"></div>
      </form>
      <div class="footer">Tunneler Admin ERP Console</div>
    </section>
  </div>
  <script>
  document.getElementById('loginForm').addEventListener('submit', async (event)=>{
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const error = document.getElementById('loginError');
    error.textContent = '';
    try{
      const resp = await fetch('/api/login', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username, password}),
      });
      const payload = await resp.json();
      if(!resp.ok || !payload.ok){
        throw new Error(payload.reason || 'login_failed');
      }
      location.href = payload.redirect || '/dashboard';
    }catch(err){
      error.textContent = err.message === 'invalid_credentials' ? '계정 정보가 올바르지 않습니다.' : `로그인 실패: ${err.message}`;
    }
  });
  </script>
</body>
</html>
"""

DASH_HTML = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Tunneler Admin</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root{
  --bg:#eef3ea;
  --bg-accent:#dde7d2;
  --surface:#fffdf8;
  --surface-soft:#f5f0e4;
  --surface-dark:#13211b;
  --ink:#16231d;
  --muted:#66756d;
  --line:#d6ddcf;
  --brand:#1f6b47;
  --brand-strong:#0f4f32;
  --danger:#b04034;
  --warning:#b87c23;
  --shadow:0 20px 50px rgba(16, 26, 21, 0.12);
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{
  font-family:"IBM Plex Sans","Noto Sans KR",sans-serif;
  color:var(--ink);
  background:
    radial-gradient(circle at top left, rgba(31,107,71,.14), transparent 26%),
    radial-gradient(circle at top right, rgba(184,124,35,.12), transparent 24%),
    linear-gradient(180deg, var(--bg-accent) 0%, var(--bg) 160px, #edf2ea 100%);
}
a{color:inherit;text-decoration:none}
button,input,select,textarea{font:inherit}
#toast{position:fixed;top:18px;right:18px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:#122018;color:#edf6ef;padding:11px 14px;border-radius:14px;box-shadow:var(--shadow);font-size:14px;border:1px solid rgba(255,255,255,.08)}
#modalOverlay{position:fixed;inset:0;background:rgba(10,18,14,.54);display:none;align-items:center;justify-content:center;z-index:9998;padding:18px}
.modal-card{width:min(1040px,100%);background:var(--surface);border-radius:28px;box-shadow:0 30px 80px rgba(17,30,24,.34);border:1px solid rgba(19,33,27,.08);overflow:hidden}
.modal-head{padding:18px 22px;font-weight:700;font-size:18px;border-bottom:1px solid var(--line);background:linear-gradient(180deg, rgba(31,107,71,.08), transparent)}
.modal-body{padding:20px 22px;max-height:72vh;overflow:auto;background:var(--surface)}
.modal-foot{padding:16px 22px;display:flex;gap:10px;border-top:1px solid var(--line);background:var(--surface-soft)}
.modal-foot .spacer{flex:1}
.grid-auto{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.badge,.pill{
  display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:999px;
  background:#f2f7f3;border:1px solid #cfe0d2;color:#1a3c2b;font-size:12px;font-weight:600
}
.badge{cursor:pointer}
.badge:hover{background:#e4f0e7}
.app-shell{display:grid;grid-template-columns:290px minmax(0,1fr);min-height:100vh}
.rail{
  position:sticky;top:0;height:100vh;padding:28px 22px;border-right:1px solid rgba(19,33,27,.09);
  background:linear-gradient(180deg, rgba(19,33,27,.96), rgba(24,46,36,.96));
  color:#eff7f1;display:flex;flex-direction:column;gap:24px
}
.brand-card{padding:18px;border-radius:24px;background:linear-gradient(145deg, rgba(255,255,255,.08), rgba(255,255,255,.02));border:1px solid rgba(255,255,255,.08)}
.brand-eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:#b7c8be}
.brand-title{margin:8px 0 10px;font-size:28px;font-weight:700;letter-spacing:-.03em}
.rail-copy{font-size:14px;line-height:1.6;color:#d5e2d8}
.rail-nav{display:flex;flex-direction:column;gap:10px}
.rail-link{
  width:100%;padding:12px 14px;border-radius:16px;border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.04);color:#eff7f1;text-align:left;font-weight:600;cursor:pointer;transition:.18s ease
}
.rail-link:hover{background:rgba(255,255,255,.08);transform:translateX(2px)}
.rail-link.active{background:#edf6ef;color:#112018;border-color:#edf6ef;box-shadow:0 12px 28px rgba(10,18,14,.18)}
.rail-metric{padding:14px 16px;border-radius:20px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.06)}
.rail-metric .label{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:#b7c8be}
.rail-metric .value{margin-top:8px;font-size:18px;font-weight:600}
.workspace{padding:28px 28px 34px}
.hero{
  display:flex;justify-content:space-between;gap:18px;align-items:flex-start;padding:24px;border-radius:30px;
  background:linear-gradient(135deg, rgba(255,253,248,.95), rgba(247,242,231,.92));
  border:1px solid rgba(19,33,27,.08);box-shadow:var(--shadow);margin-bottom:22px
}
.hero h1{margin:6px 0 10px;font-size:36px;line-height:1.05;letter-spacing:-.04em}
.hero p{margin:0;color:var(--muted);max-width:760px;line-height:1.6}
.hero-actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}
.top-strip{display:grid;grid-template-columns:minmax(520px,1.9fr) repeat(2,minmax(220px,1fr));gap:16px;margin-bottom:22px}
.btn{
  appearance:none;border:none;border-radius:16px;padding:12px 16px;font-weight:600;cursor:pointer;
  display:inline-flex;align-items:center;justify-content:center;gap:8px;transition:.18s ease;
}
.btn:hover{transform:translateY(-1px)}
.btn-primary{background:var(--brand);color:#f4fbf7;box-shadow:0 12px 30px rgba(31,107,71,.22)}
.btn-secondary{background:#e6ede1;color:var(--ink)}
.btn-ghost{background:#f8faf6;color:var(--ink);border:1px solid var(--line)}
.btn-danger{background:var(--danger);color:#fff2ee}
.btn-warning{background:#fff6e4;color:#8b5b17;border:1px solid rgba(184,124,35,.24)}
.btn-mini{padding:8px 11px;border-radius:12px;font-size:13px}
.hero-meta{margin-top:14px;display:flex;flex-wrap:wrap;gap:10px}
.stats-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:16px;margin-bottom:22px}
.stat-card,.panel,.tunnel-card{background:var(--surface);border:1px solid rgba(19,33,27,.08);box-shadow:var(--shadow)}
.stat-card{border-radius:24px;padding:18px}
.stat-card .label{font-size:13px;color:var(--muted)}
.stat-card .value{margin-top:8px;font-size:28px;font-weight:700;letter-spacing:-.04em}
.range-card{min-width:0}
#rangeInfo{
  font-size:clamp(13px,.95vw,16px) !important;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis
}
.throughput-line{margin-top:10px;display:flex;flex-wrap:wrap;gap:16px;font-size:14px;color:var(--muted)}
.throughput-line strong{display:inline-block;margin-left:6px;font-size:20px;color:var(--ink);letter-spacing:-.03em}
.panel{border-radius:28px;padding:20px}
.panel-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:16px}
.panel-head h2,.panel-head h3{margin:0;font-size:22px;letter-spacing:-.03em}
.panel-head p{margin:4px 0 0;color:var(--muted);font-size:14px}
.panel-actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}
.tunnel-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.tunnel-card{border-radius:26px;padding:18px;display:flex;flex-direction:column;gap:16px;background:linear-gradient(180deg,#fffdf8,#f5f0e4)}
.tunnel-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.tunnel-head h3{margin:0;font-size:23px;letter-spacing:-.03em}
.tunnel-meta{display:flex;gap:8px;flex-wrap:wrap}
.tunnel-actions{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end}
.info-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.info-cell{padding:12px 14px;border-radius:18px;background:rgba(255,255,255,.68);border:1px solid rgba(19,33,27,.06)}
.info-cell .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.info-cell .value{margin-top:6px;font-size:16px;font-weight:600}
.mapping-block{padding:14px 16px;border-radius:18px;background:rgba(255,255,255,.72);border:1px solid rgba(19,33,27,.06)}
.mapping-block h4{margin:0 0 10px;font-size:15px}
.chip-row{display:flex;flex-wrap:wrap;gap:8px}
.chip{
  display:inline-flex;align-items:center;gap:6px;padding:8px 10px;border-radius:14px;background:#f7fbf7;
  border:1px solid #dbe8dc;font-size:13px
}
.chip strong{font-weight:700}
.ops-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin:22px 0}
.field{display:flex;flex-direction:column;gap:8px}
.field label{font-size:13px;color:var(--muted);font-weight:600}
.field input,.field select,.field textarea{
  width:100%;border:1px solid var(--line);border-radius:16px;padding:12px 14px;background:#fffdfa;color:var(--ink)
}
.field textarea{min-height:140px;resize:vertical}
.field-help{font-size:13px;color:var(--muted);line-height:1.5}
.schedule-row{display:flex;flex-wrap:wrap;gap:8px}
.token-table,.log-table,.bw-table{width:100%;border-collapse:separate;border-spacing:0;font-size:14px}
.token-table th,.token-table td,.bw-table th,.bw-table td{padding:12px 10px;border-bottom:1px solid var(--line);text-align:left}
.token-table th,.bw-table th{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
#logs{
  margin:0;background:#08100d;color:#8de0a9;border-radius:22px;padding:18px;
  min-height:300px;max-height:420px;overflow:auto;border:1px solid rgba(255,255,255,.06);
  font-family:"IBM Plex Mono",monospace;font-size:12px;line-height:1.6
}
.section-stack{display:flex;flex-direction:column;gap:16px}
.content-section{display:block}
.content-section.hidden{display:none}
.empty-state{padding:28px;border-radius:22px;border:1px dashed #c4d2c6;background:rgba(255,255,255,.46);text-align:center;color:var(--muted)}
.border-top{border-top:1px solid var(--line)}
.ip-actions{display:flex;flex-wrap:wrap;gap:8px}
.ip-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}
.ip-row:last-child{border-bottom:none}
.subtle{color:var(--muted)}
.modal-stack{display:flex;flex-direction:column;gap:16px}
.meta-row{display:flex;flex-wrap:wrap;gap:10px}
.manage-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.action-tile{
  appearance:none;
  padding:16px 18px;border-radius:20px;border:1px solid rgba(19,33,27,.08);background:linear-gradient(180deg,#fffdf8,#f6f0e4);
  display:flex;align-items:center;justify-content:space-between;gap:12px;cursor:pointer;transition:.18s ease
}
.action-tile:hover{transform:translateY(-1px);box-shadow:0 16px 28px rgba(19,33,27,.1)}
.action-copy strong{display:block;font-size:16px}
.action-copy{flex:1;text-align:left}
.action-copy span{display:block;margin-top:4px;font-size:13px;color:var(--muted)}
.mapping-list{display:flex;flex-direction:column;gap:10px}
.search-inline{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.search-inline input{
  min-width:0;flex:1;border:1px solid var(--line);border-radius:14px;padding:10px 12px;background:#fffdfa;color:var(--ink)
}
.calendar-shell{display:flex;flex-direction:column;gap:12px}
.calendar-head{display:flex;justify-content:space-between;align-items:center;gap:12px}
.calendar-grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px}
.calendar-weekday{
  text-align:center;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;padding-bottom:4px
}
.calendar-cell,.calendar-empty{
  min-height:88px;border-radius:18px;border:1px solid rgba(19,33,27,.08);background:rgba(255,255,255,.72);padding:10px
}
.calendar-empty{background:rgba(255,255,255,.42);border-style:dashed}
.calendar-day{
  width:100%;height:100%;border:none;background:transparent;padding:0;display:flex;flex-direction:column;align-items:flex-start;justify-content:space-between;
  color:var(--ink);cursor:pointer
}
.calendar-day.disabled{cursor:default;color:var(--muted)}
.calendar-day.has-data{font-weight:700}
.calendar-day .count{
  display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:700;background:#edf6ef;color:#0f4f32
}
.list-stack{display:flex;flex-direction:column;gap:10px}
.pager{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:12px}
.pager-controls{display:flex;gap:8px}
.pager-info{font-size:13px;color:var(--muted)}
.session-meta{display:flex;flex-wrap:wrap;gap:8px}
.mapping-row{
  display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 16px;border-radius:18px;
  border:1px solid rgba(19,33,27,.08);background:rgba(255,255,255,.76)
}
.mapping-meta strong{display:block;font-size:15px}
.mapping-meta span{display:block;margin-top:4px;font-size:13px;color:var(--muted)}
.source-tag{
  display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:700;
  text-transform:uppercase;letter-spacing:.06em;background:#e6ede1;color:#204130
}
.source-tag.server{background:#dce9df;color:#0f4f32}
.source-tag.client{background:#f1efe5;color:#6a5422}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.footer-note{display:flex;justify-content:space-between;gap:12px;align-items:center;padding-top:16px;margin-top:24px;border-top:1px solid rgba(19,33,27,.08);color:var(--muted);font-size:13px}
@media (max-width: 1180px){
  .app-shell{grid-template-columns:1fr}
  .rail{position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(255,255,255,.08)}
  .top-strip,.stats-grid,.tunnel-grid,.ops-grid,.manage-actions,.form-grid{grid-template-columns:1fr}
  .hero{flex-direction:column}
  .hero-actions{justify-content:flex-start}
}
@media (max-width: 720px){
  .workspace{padding:18px}
  .hero{padding:20px}
  .hero h1{font-size:28px}
  .panel,.stat-card,.tunnel-card{padding:16px}
}
</style>
</head>
<body>
<div id="toast"></div>
<div id="modalOverlay"><div class="modal-card">
  <div class="modal-head" id="modalTitle">Modal</div>
  <div class="modal-body" id="modalBody"></div>
  <div class="modal-foot">
    <div class="spacer"></div>
    <button id="modalCancel" class="btn btn-secondary btn-mini">취소</button>
    <button id="modalOk" class="btn btn-primary btn-mini">확인</button>
  </div>
</div></div>

<div class="app-shell">
  <aside class="rail">
    <div class="brand-card">
      <div class="brand-eyebrow">Server Console</div>
      <div class="brand-title">Tunneler</div>
      <div class="rail-copy">관리 항목을 왼쪽에서 선택하고, 활성 터널은 메인 대시보드에서 관리합니다.</div>
    </div>
    <nav class="rail-nav">
      <button class="rail-link active" data-section="overviewSection">메인 대시보드</button>
      <button class="rail-link" data-section="accessSection">대시보드 접근 제한</button>
      <button class="rail-link" data-section="tokensSection">클라이언트 토큰</button>
      <button class="rail-link" data-section="scheduleSection">접속 허용 시간대</button>
      <button class="rail-link" data-section="denySection">전역 접근 차단</button>
      <button class="rail-link" data-section="botSection">봇 / 크롤러 차단</button>
      <button class="rail-link" data-section="bandwidthSection">실시간 대역폭</button>
      <button class="rail-link" data-section="logsSection">로그 아카이브</button>
    </nav>
  </aside>

  <main class="workspace">
    <section class="hero">
      <div>
        <h1>Tunneler Server Admin Dashboard</h1>
        <div class="hero-meta">
          <span class="pill">활성 서브도메인 <strong id="statSubs">-</strong></span>
          <span class="pill">실시간 터널 <strong id="bwSubs">0</strong></span>
        </div>
      </div>
      <div class="hero-actions">
        <button id="openAgg" class="btn btn-primary">집계 / 제한</button>
        <button id="prevLogsBtn" class="btn btn-secondary">이전 로그 보기</button>
        <button id="refreshBtn" class="btn btn-ghost">수동 새로고침</button>
        <a href="/logout" class="btn btn-secondary">로그아웃</a>
      </div>
    </section>

    <section class="top-strip">
      <div class="stat-card range-card">
        <div class="label">Port Range</div>
        <div class="value" id="rangeInfo">-</div>
      </div>
      <div class="stat-card">
        <div class="label">Server Clock</div>
        <div class="value" id="serverClock">-</div>
      </div>
      <div class="stat-card">
        <div class="label">Live Throughput</div>
        <div class="throughput-line">
          <span>In <strong id="totalIn">0 B/s</strong></span>
          <span>Out <strong id="totalOut">0 B/s</strong></span>
        </div>
      </div>
    </section>

    <section id="overviewSection" class="content-section">
      <section class="stats-grid" id="stats">
        <div class="stat-card"><div class="label">TCP 포트 수</div><div class="value" id="statTCP">-</div></div>
        <div class="stat-card"><div class="label">UDP 포트 수</div><div class="value" id="statUDP">-</div></div>
        <div class="stat-card"><div class="label">현재 접속 IP</div><div class="value" id="statLiveIps">0</div></div>
        <div class="stat-card"><div class="label">운영 토큰 수</div><div class="value" id="statTokens">0</div></div>
        <div class="stat-card"><div class="label">전역 차단 규칙</div><div class="value" id="statGlobalDeny">0</div></div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>활성 터널</h2>
          </div>
        </div>
        <div id="list" class="tunnel-grid"></div>
      </section>
    </section>

    <section id="accessSection" class="content-section hidden">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h3>대시보드 접근 제한</h3>
            <p>허용할 IP 또는 CIDR만 입력합니다. 비워두면 제한이 없습니다.</p>
          </div>
        </div>
        <div class="field">
          <label for="ipAllow">허용 목록</label>
          <input id="ipAllow" placeholder="예: 1.2.3.4, 10.0.0.0/24"/>
        </div>
        <div class="panel-actions" style="margin-top:14px">
          <button id="saveIp" class="btn btn-primary btn-mini">저장</button>
        </div>
      </section>
    </section>

    <section id="tokensSection" class="content-section hidden">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h3>클라이언트 토큰</h3>
            <p>화이트리스트를 저장하고 즉시 무효화할 수 있습니다.</p>
          </div>
        </div>
        <div class="field">
          <label for="tokens">토큰 목록</label>
          <input id="tokens" placeholder="예: AAA, BBB, TEAM-ALPHA"/>
        </div>
        <div class="panel-actions" style="margin-top:14px">
          <button id="saveTok" class="btn btn-primary btn-mini">토큰 저장</button>
        </div>
        <div style="margin-top:16px">
          <div class="subtle" style="margin-bottom:10px;font-size:13px">마지막 사용 내역 / 빠른 무효화</div>
          <div id="tokMeta"></div>
        </div>
      </section>
    </section>

    <section id="scheduleSection" class="content-section hidden">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h3>접속 허용 시간대</h3>
            <p>전역 정책입니다. 비워두면 24시간 허용됩니다.</p>
          </div>
        </div>
        <div id="schList" class="schedule-row"></div>
        <div class="panel-actions" style="margin-top:14px">
          <button id="saveSch" class="btn btn-secondary btn-mini">시간대 편집</button>
        </div>
      </section>
    </section>

    <section id="denySection" class="content-section hidden">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h3>전역 접근 차단</h3>
            <p>모든 터널에 공통 적용되는 외부 접근 IP/CIDR 차단 규칙입니다.</p>
          </div>
        </div>
        <div class="field">
          <label for="denyIp">차단 규칙</label>
          <input id="denyIp" placeholder="예: 203.0.113.5, 10.0.0.0/8"/>
        </div>
        <div class="panel-actions" style="margin-top:14px">
          <button id="saveDeny" class="btn btn-danger btn-mini">차단 저장</button>
        </div>
      </section>
    </section>

    <section id="botSection" class="content-section hidden">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h3>봇 / 크롤러 차단</h3>
            <p>HTTP User-Agent와 다중 포트/경로 스캔 패턴을 기준으로 HTTP, TCP, UDP 모두 차단합니다.</p>
          </div>
        </div>
        <div class="field" style="margin-bottom:10px">
          <label><input id="botBlockEnabled" type="checkbox" style="width:auto;margin-right:8px"> 봇 차단 활성화</label>
        </div>
        <div class="field">
          <label><input id="botBlockEmptyUa" type="checkbox" style="width:auto;margin-right:8px"> 빈 User-Agent 즉시 차단(HTTP)</label>
        </div>
        <div class="field">
          <label for="botRules">차단 키워드</label>
          <textarea id="botRules" placeholder="한 줄에 하나씩 입력"></textarea>
        </div>
        <div class="panel-actions" style="margin-top:14px">
          <button id="saveBot" class="btn btn-secondary btn-mini">봇 차단 저장</button>
        </div>
      </section>
    </section>

    <section id="bandwidthSection" class="content-section hidden">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h3>실시간 대역폭</h3>
            <p>초당 In / Out 트래픽을 터널별로 집계합니다.</p>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="bw-table">
            <thead>
              <tr><th>Subdomain</th><th>In</th><th>Out</th></tr>
            </thead>
            <tbody id="bwBody"></tbody>
          </table>
        </div>
      </section>
    </section>

    <section id="logsSection" class="content-section hidden">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h3>로그 아카이브</h3>
            <p>기본은 tail 미리보기만 빠르게 로드하고, 필요할 때 전체 로그를 다시 읽습니다.</p>
          </div>
          <div class="panel-actions">
            <select id="logSel" class="field" style="min-width:220px;padding:0">
              <option value="">로그 선택</option>
            </select>
            <button id="loadSel" class="btn btn-secondary btn-mini">선택 로그 보기</button>
            <button id="clearLog" class="btn btn-ghost btn-mini">실시간 로그 지우기</button>
          </div>
        </div>
        <pre id="logs"></pre>
      </section>
    </section>

    <div class="footer-note">
      <div>rhkr8521 Tunneler Admin ERP Console</div>
      <div>© rhkr8521</div>
    </div>
  </main>
</div>

<script>
let ws;
let lastSnapshot = null;
let lastBandwidth = {items:{}, total:{tx:0, rx:0}};
let snapshotBusy = false;
let snapshotQueued = false;
let autoRefreshHandle = null;

/* ===== 토스트/모달 유틸 ===== */
function showToast(msg, type='info', ms=2200){
  const t = document.createElement('div');
  t.className = 'toast';
  if(type==='ok'){ t.style.background='#065f46'; t.style.color='#ecfdf5'; }
  if(type==='warn'){ t.style.background='#78350f'; t.style.color='#fef3c7'; }
  if(type==='err'){ t.style.background='#7f1d1d'; t.style.color='#fee2e2'; }
  t.textContent = msg;
  document.getElementById('toast').appendChild(t);
  setTimeout(()=>{ t.remove(); }, ms);
}
function confirmAsync(message){
  return new Promise((resolve)=>{
    const ov = document.getElementById('modalOverlay');
    document.getElementById('modalTitle').textContent = '확인';
    document.getElementById('modalBody').innerHTML = `<div class="text-slate-700">${message}</div>`;
    const ok = document.getElementById('modalOk');
    const no = document.getElementById('modalCancel');
    ok.textContent = '확인';
    no.textContent = '취소';
    const close = () => { ov.style.display='none'; ok.onclick=null; no.onclick=null; }
    ok.onclick = ()=>{ resolve(true); close(); }
    no.onclick = ()=>{ resolve(false); close(); }
    ov.style.display='flex';
  });
}
function openCustomModal(title, html, okLabel='저장'){
  return new Promise((resolve)=>{
    const ov = document.getElementById('modalOverlay');
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = html;
    const ok = document.getElementById('modalOk'); ok.textContent = okLabel;
    const no = document.getElementById('modalCancel');
    no.textContent = '취소';
    const close = () => { ov.style.display='none'; ok.onclick=null; no.onclick=null; }
    ok.onclick = ()=>{ resolve(true); close(); }
    no.onclick = ()=>{ resolve(false); close(); }
    ov.style.display='flex';
  });
}
function closeActiveModal(){
  const cancelBtn = document.getElementById('modalCancel');
  if(cancelBtn && typeof cancelBtn.onclick === 'function'){
    cancelBtn.onclick();
    return;
  }
  document.getElementById('modalOverlay').style.display = 'none';
}
function jumpFromModal(next){
  closeActiveModal();
  setTimeout(next, 40);
}
function switchSection(sectionId){
  document.querySelectorAll('.content-section').forEach(section=>{
    section.classList.toggle('hidden', section.id !== sectionId);
  });
  document.querySelectorAll('.rail-link').forEach(link=>{
    link.classList.toggle('active', link.dataset.section === sectionId);
  });
}

/* ===== API 헬퍼 ===== */
async function api(path, opts={}){
  const r = await fetch(path, opts);
  if(r.status === 401){
    location.href = '/login';
    throw new Error('unauthorized');
  }
  const ct = r.headers.get('content-type') || '';
  const payload = ct.includes('application/json') ? await r.json() : await r.text();
  if(!r.ok){
    const reason = typeof payload === 'string' ? payload : (payload.reason || payload.message || 'request_failed');
    throw new Error(reason);
  }
  return payload;
}

/* ===== 포맷 ===== */
function escapeHtml(value){
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
function formatRate(bytesPerSec){
  const b = Number(bytesPerSec||0);
  if(b < 1024) return `${b.toFixed(0)} B/s`;
  const kb = b / 1024;
  if(kb < 1024) return `${kb.toFixed(2)} KB/s`;
  const mb = kb / 1024;
  return `${mb.toFixed(2)} MB/s`;
}
function formatBytes(b){
  b = Number(b||0);
  const units = ['B','KB','MB','GB','TB'];
  let i=0;
  while(b>=1024 && i<units.length-1){ b/=1024; i++; }
  return `${b.toFixed(i?2:0)} ${units[i]}`;
}
function formatAxisBytes(b){
  b = Number(b||0);
  if(b === 0) return '0 B';
  if(Math.abs(b) < 1024) return `${b.toFixed(0)} B`;
  const units = ['KB','MB','GB','TB'];
  let val = b / 1024;
  let idx = 0;
  while(Math.abs(val) >= 1024 && idx < units.length - 1){ val /= 1024; idx++; }
  return `${val.toFixed(val >= 100 ? 0 : val >= 10 ? 1 : 2)} ${units[idx]}`;
}
function formatLogMeta(meta){
  if(!meta) return '';
  const size = meta.size != null ? formatBytes(meta.size) : '';
  const modified = meta.modified_at ? meta.modified_at.replace('T',' ') : '';
  return [size, modified].filter(Boolean).join(' · ');
}
function syncInputValue(id, value){
  const el = document.getElementById(id);
  if(!el || document.activeElement === el) return;
  el.value = value;
}
function syncCheckboxValue(id, checked){
  const el = document.getElementById(id);
  if(!el || document.activeElement === el) return;
  el.checked = Boolean(checked);
}
function formatMonthLabel(key){
  const [year, month] = String(key || '').split('-').map(Number);
  if(!year || !month) return key || '';
  return `${year}.${String(month).padStart(2,'0')}`;
}
function monthKeyFromDate(date){
  return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}`;
}
function parseMonthKey(key){
  const [year, month] = String(key || '').split('-').map(Number);
  return new Date(year || new Date().getFullYear(), (month || 1) - 1, 1);
}
function shiftMonth(key, diff){
  const date = parseMonthKey(key);
  date.setMonth(date.getMonth() + diff, 1);
  return monthKeyFromDate(date);
}
function renderPager(page, pages){
  return `
    <div class="pager">
      <div class="pager-info">${page} / ${pages} 페이지</div>
      <div class="pager-controls">
        <button class="btn btn-ghost btn-mini" data-page-nav="prev">이전</button>
        <button class="btn btn-ghost btn-mini" data-page-nav="next">다음</button>
      </div>
    </div>`;
}
function renderBandwidthTable(payload = lastBandwidth){
  const tbody = document.getElementById('bwBody');
  if(!tbody) return;
  const snapshotTunnels = (lastSnapshot && lastSnapshot.tunnels) || {};
  const items = (payload && payload.items) || {};
  const total = (payload && payload.total) || {tx:0, rx:0};
  document.getElementById('totalIn').textContent = formatRate(total.rx || 0);
  document.getElementById('totalOut').textContent = formatRate(total.tx || 0);
  const subs = Array.from(new Set([...Object.keys(snapshotTunnels), ...Object.keys(items)])).sort();
  tbody.innerHTML = '';
  if(!subs.length){
    tbody.innerHTML = `<tr><td colspan="3"><span class="subtle">표시할 터널이 없습니다.</span></td></tr>`;
    return;
  }
  subs.forEach(sub=>{
    const v = items[sub] || {tx:0, rx:0};
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(sub)}</td><td>${formatRate(v.rx||0)}</td><td>${formatRate(v.tx||0)}</td>`;
    tbody.appendChild(tr);
  });
}

/* ===== 로그 목록 ===== */
async function loadLogList(){
  const d = await api('/api/logs/list');
  const sel = document.getElementById('logSel'); sel.innerHTML='';
  (d.files||[]).forEach(file=>{
    const o=document.createElement('option');
    o.value=file.name;
    o.textContent=`${file.name} (${formatLogMeta(file)})`;
    sel.appendChild(o);
  });
}
async function loadLogListAndOpenFirst(){
  const d = await api('/api/logs/list');
  const sel = document.getElementById('logSel'); sel.innerHTML='';
  (d.files||[]).forEach(file=>{
    const o=document.createElement('option');
    o.value=file.name;
    o.textContent=`${file.name} (${formatLogMeta(file)})`;
    sel.appendChild(o);
  });
  if ((d.files||[]).length > 0) {
    sel.selectedIndex = 0;
    const result = await api('/api/logs/get?fmt=json&mode=tail&lines=900&name='+encodeURIComponent(sel.value));
    const pre=document.getElementById('logs');
    pre.textContent = (result.truncated ? `[tail preview] ${formatLogMeta(result.meta)}\n\n` : '') + (result.text || '');
    pre.scrollTop = pre.scrollHeight;
    showToast('로그 로드 완료','ok');
  } else {
    showToast('표시할 로그가 없습니다.','warn');
  }
}

/* ===== 스냅샷 ===== */
async function loadSnapshot(){
  if(snapshotBusy){
    snapshotQueued = true;
    return lastSnapshot;
  }
  snapshotBusy = true;
  try{
    const d = await api('/api/tunnels');
    if(!d) return lastSnapshot;
    lastSnapshot = d;
    const t=d.tunnels||{}; const keys=Object.keys(t).sort();
    const liveIps = keys.reduce((acc, key)=> acc + ((t[key].current_ips||[]).length), 0);
    const rangeInfo = document.getElementById('rangeInfo');
    rangeInfo.textContent = d.range || '';
    rangeInfo.title = d.range || '';
    document.getElementById('serverClock').textContent = (d.server_time || '-').replace('T',' ');
    document.getElementById('statSubs').textContent = keys.length;
    document.getElementById('statTCP').textContent = keys.reduce((a,k)=>a+Object.keys(t[k].tcp||{}).length,0);
    document.getElementById('statUDP').textContent = keys.reduce((a,k)=>a+Object.keys(t[k].udp||{}).length,0);
    document.getElementById('bwSubs').textContent = keys.length;
    document.getElementById('statLiveIps').textContent = liveIps;
    document.getElementById('statTokens').textContent = (d.tokens||[]).length;
    document.getElementById('statGlobalDeny').textContent = (d.tunnel_ip_deny||[]).length;

    const list=document.getElementById('list'); list.innerHTML="";
    if(!keys.length){
      list.innerHTML = `<div class="empty-state">현재 연결된 클라이언트가 없습니다. 클라이언트가 다시 연결되면 여기서 포트와 IP를 바로 제어할 수 있습니다.</div>`;
    }
    keys.forEach(sub=>{
      const o=t[sub]||{};
      const tcpItems=o.tcp_items||[];
      const udpItems=o.udp_items||[];
      const tcpList=tcpItems.map(item=>
        `<span class="chip">${item.managed ? 'S' : 'C'} <strong>${escapeHtml(item.name)}</strong> ${escapeHtml(item.remote_port)}</span>`
      ).join("");
      const udpList=udpItems.map(item=>
        `<span class="chip">${item.managed ? 'S' : 'C'} <strong>${escapeHtml(item.name)}</strong> ${escapeHtml(item.remote_port)}</span>`
      ).join("");
      const card=document.createElement('div');
      card.className='tunnel-card';

      const h=document.createElement('div'); h.className='tunnel-head';
      const title=document.createElement('div');
      title.innerHTML = `<h3>${escapeHtml(sub)}</h3>`;
      h.appendChild(title);

      const btnWrap=document.createElement('div'); btnWrap.className='tunnel-actions';
      const manageBtn=document.createElement('button');
      manageBtn.className='btn btn-primary btn-mini';
      manageBtn.textContent='터널 관리';
      manageBtn.onclick=()=> openTunnelManageModal(sub);
      btnWrap.appendChild(manageBtn);

      h.appendChild(btnWrap);
      card.appendChild(h);

      const info=document.createElement('div'); info.className='info-grid';
      info.innerHTML = `
        <div class="info-cell"><div class="label">Current IP</div><div class="value">${escapeHtml((o.current_ips||[]).length)}</div></div>
        <div class="info-cell"><div class="label">TCP Streams</div><div class="value">${escapeHtml(o.tcp_streams||0)}</div></div>
        <div class="info-cell"><div class="label">UDP Flows</div><div class="value">${escapeHtml(o.udp_flows||0)}</div></div>
        <div class="info-cell"><div class="label">Managed Ports</div><div class="value">${escapeHtml((o.managed_tcp||[]).length + (o.managed_udp||[]).length)}</div></div>`;
      card.appendChild(info);

      const sec1=document.createElement('div'); sec1.className='mapping-block';
      sec1.innerHTML='<h4>TCP 포트</h4><div class="chip-row">'+(tcpList||'<span class="subtle">등록된 TCP 포트가 없습니다.</span>')+'</div>';
      const sec2=document.createElement('div'); sec2.className='mapping-block';
      sec2.innerHTML='<h4>UDP 포트</h4><div class="chip-row">'+(udpList||'<span class="subtle">등록된 UDP 포트가 없습니다.</span>')+'</div>';

      card.appendChild(sec1);
      card.appendChild(sec2);
      list.appendChild(card);
    });

    syncInputValue('ipAllow', (d.admin_ip_allow||[]).join(', '));
    syncInputValue('tokens', (d.tokens||[]).join(', '));
    syncInputValue('denyIp', (d.tunnel_ip_deny||[]).join(', '));
    syncCheckboxValue('botBlockEnabled', (d.bot_blocking||{}).enabled);
    syncCheckboxValue('botBlockEmptyUa', (d.bot_blocking||{}).block_empty_ua);
    syncInputValue('botRules', ((d.bot_blocking||{}).rules || []).join('\\n'));

    renderBandwidthTable();
    await renderGlobalScheduleList(d);
    return d;
  }finally{
    snapshotBusy = false;
    if(snapshotQueued){
      snapshotQueued = false;
      setTimeout(()=>{ loadSnapshot(); }, 50);
    }
  }
}

async function editTunnelSchedule(sub){
  try{
    const cur = await api(`/api/admin/schedule/${encodeURIComponent(sub)}`);
    const items = await openScheduleModal(sub, cur.items||[]);
    if(items===null) return;
    await api(`/api/admin/schedule/${encodeURIComponent(sub)}`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(items)
    });
    await loadSnapshot();
    await renderGlobalScheduleList();
    showToast('시간대 정책을 저장했습니다.','ok');
  }catch(err){
    showToast(`시간대 저장 실패: ${err.message}`,'err',2800);
  }
}

function renderMappingSummary(items, proto){
  if(!items.length) return `<span class="subtle">등록된 ${proto.toUpperCase()} 포트가 없습니다.</span>`;
  return `<div class="chip-row">${items.map(item=>
    `<span class="chip">${item.managed ? 'S' : 'C'} <strong>${escapeHtml(item.name)}</strong> ${escapeHtml(item.remote_port)}</span>`
  ).join('')}</div>`;
}

async function openTunnelManageModal(sub){
  const tunnel = ((lastSnapshot&&lastSnapshot.tunnels)||{})[sub];
  if(!tunnel){
    showToast('선택한 터널이 더 이상 연결되어 있지 않습니다.','warn');
    await loadSnapshot();
    return;
  }
  const html = `
    <div class="modal-stack">
      <section class="panel" style="box-shadow:none">
        <div class="panel-head">
          <div>
            <h3>${escapeHtml(sub)}</h3>
            <p>연결 상태와 제어 기능을 한 곳에서 관리합니다.</p>
          </div>
        </div>
        <div class="meta-row">
          <span class="pill">WS ${escapeHtml(tunnel.peer_ip || '-')}</span>
          <span class="pill">연결 ${escapeHtml((tunnel.connected_at || '-').replace('T',' '))}</span>
          <span class="pill">차단 ${escapeHtml((tunnel.blocked_ips||[]).length)}</span>
        </div>
        <div class="info-grid" style="margin-top:16px">
          <div class="info-cell"><div class="label">Current IP</div><div class="value">${escapeHtml((tunnel.current_ips||[]).length)}</div></div>
          <div class="info-cell"><div class="label">TCP Streams</div><div class="value">${escapeHtml(tunnel.tcp_streams||0)}</div></div>
          <div class="info-cell"><div class="label">UDP Flows</div><div class="value">${escapeHtml(tunnel.udp_flows||0)}</div></div>
          <div class="info-cell"><div class="label">Managed Ports</div><div class="value">${escapeHtml((tunnel.managed_tcp||[]).length + (tunnel.managed_udp||[]).length)}</div></div>
        </div>
      </section>
      <section class="panel" style="box-shadow:none">
        <div class="panel-head">
          <div>
            <h3>제어 작업</h3>
            <p>버튼을 분리해두지 않고 이 모달에서 일괄 제어합니다.</p>
          </div>
        </div>
        <div class="manage-actions">
          <button class="action-tile" data-action="limit"><span class="action-copy"><strong>제한</strong><span>대역폭 제한 저장</span></span><span class="source-tag server">관리</span></button>
          <button class="action-tile" data-action="schedule"><span class="action-copy"><strong>시간대</strong><span>허용 시간대 설정</span></span><span class="source-tag server">정책</span></button>
          <button class="action-tile" data-action="ports"><span class="action-copy"><strong>포트 관리</strong><span>추가 / 삭제 즉시 반영</span></span><span class="source-tag server">ports</span></button>
          <button class="action-tile" data-action="clients"><span class="action-copy"><strong>접속 IP</strong><span>실시간 차단 / 해제</span></span><span class="source-tag client">ip</span></button>
          <button class="action-tile" data-action="restart"><span class="action-copy"><strong>재연결</strong><span>클라이언트 프로그램 재시작</span></span><span class="source-tag client">restart</span></button>
          <button class="action-tile" data-action="disconnect"><span class="action-copy"><strong>Disconnect</strong><span>현재 세션만 대기 상태 전환</span></span><span class="source-tag client">stop</span></button>
        </div>
      </section>
      <section class="panel" style="box-shadow:none">
        <div class="panel-head">
          <div>
            <h3>현재 포트</h3>
            <p>포트 관리에서 추가/삭제하면 연결 중인 클라이언트에도 즉시 전달됩니다.</p>
          </div>
        </div>
        <div class="mapping-block">
          <h4>TCP 포트</h4>
          ${renderMappingSummary(tunnel.tcp_items||[], 'tcp')}
        </div>
        <div class="mapping-block" style="margin-top:12px">
          <h4>UDP 포트</h4>
          ${renderMappingSummary(tunnel.udp_items||[], 'udp')}
        </div>
      </section>
    </div>`;
  const p = openCustomModal(`터널 관리 (${sub})`, html, '닫기');
  const body = document.getElementById('modalBody');
  body.querySelector('[data-action="limit"]').onclick = ()=> jumpFromModal(()=> openLimitModal(sub));
  body.querySelector('[data-action="schedule"]').onclick = ()=> jumpFromModal(()=> editTunnelSchedule(sub));
  body.querySelector('[data-action="ports"]').onclick = ()=> jumpFromModal(()=> openPortManageModal(sub));
  body.querySelector('[data-action="clients"]').onclick = ()=> jumpFromModal(()=> openClientsModal(sub));
  body.querySelector('[data-action="restart"]').onclick = ()=> jumpFromModal(async ()=>{
    const ok = await confirmAsync(`${escapeHtml(sub)} 클라이언트를 재시작할까요?`);
    if(!ok) return;
    try{
      await api(`/api/tunnels/${encodeURIComponent(sub)}/reconnect`, {method:'POST'});
      await loadSnapshot();
      showToast('클라이언트 재시작을 요청했습니다.','ok');
    }catch(err){
      showToast(`재연결 실패: ${err.message}`,'err',2800);
    }
  });
  body.querySelector('[data-action="disconnect"]').onclick = ()=> jumpFromModal(async ()=>{
    const ok = await confirmAsync(`${escapeHtml(sub)} 클라이언트를 현재 세션에서 대기 상태로 전환할까요?<br><br>다시 붙이려면 클라이언트 재부팅 또는 재연결 버튼 사용이 필요합니다.`);
    if(!ok) return;
    try{
      await api(`/api/tunnels/${encodeURIComponent(sub)}/disconnect`, {method:'POST'});
      await loadSnapshot();
      showToast('클라이언트를 연결 해제 상태로 전환했습니다.','ok');
    }catch(err){
      showToast(`Disconnect 실패: ${err.message}`,'err',2800);
    }
  });
  await p;
}

async function renderGlobalScheduleList(snapshot=null){
  const d = snapshot || await api('/api/tunnels');
  const gl = (d && d.access_schedules) || [];
  const box = document.getElementById('schList');
  box.innerHTML = gl.length ? 
    gl.map(x=>`<span class="pill">${escapeHtml(x.days||'all')} ${escapeHtml(x.start||'00:00')}~${escapeHtml(x.end||'23:59')}</span>`).join('') :
    '<span class="subtle">설정 없음 (24시간 허용)</span>';
}

/* ===== 토큰 메타 ===== */
async function loadTokenMeta(){
  const tm = await api('/api/admin/tokens/meta');
  const box = document.getElementById('tokMeta'); box.innerHTML='';
  const tbl = document.createElement('table'); tbl.className='token-table';
  tbl.innerHTML = `<thead>
      <tr>
        <th>Token</th><th>Last IP</th><th>Last At(UTC)</th><th></th>
      </tr></thead><tbody></tbody>`;
  const tb = tbl.querySelector('tbody');
  (tm.items||[]).forEach(r=>{
    const tr = document.createElement('tr'); tr.className='border-top';
    tr.innerHTML = `
      <td>${escapeHtml(r.token)}</td>
      <td>${escapeHtml(r.last_ip||'')}</td>
      <td>${escapeHtml(r.last_at||'')}</td>
      <td>
        <button class="btn btn-danger btn-mini" data-token="${escapeHtml(r.token)}">무효화</button>
      </td>`;
    tr.querySelector('button').onclick=async(e)=>{
      const ok = await confirmAsync('해당 토큰을 즉시 무효화할까요?');
      if(!ok) return;
      const tok = e.target.getAttribute('data-token');
      try{
        const result = await api('/api/admin/token/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})});
        await loadSnapshot();
        await loadTokenMeta();
        showToast(`토큰을 무효화했습니다.${(result.disconnected||[]).length ? ` 연결 ${result.disconnected.length}건을 종료했습니다.` : ''}`,'ok');
      }catch(err){
        showToast(`토큰 무효화 실패: ${err.message}`,'err',2800);
      }
    };
    tb.appendChild(tr);
  });
  box.appendChild(tbl);
}

/* ===== 실시간 WS ===== */
function connectWS(){
  if(ws) try{ ws.close(); }catch(e){}
  ws = new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/admin_ws');
  ws.onmessage = (ev)=>{
    try{
      const msg = JSON.parse(ev.data);
      if(msg.kind==='log'){
        const pre=document.getElementById('logs');
        pre.textContent += msg.line + "\\n"; pre.scrollTop = pre.scrollHeight;
      }else if(msg.kind==='bandwidth'){
        lastBandwidth = {
          items: msg.items || {},
          total: msg.total || {tx:0, rx:0},
        };
        renderBandwidthTable(lastBandwidth);
      }else if(['register','unregister','assigned','refresh'].includes(msg.kind)){
        loadSnapshot();
        loadTokenMeta().catch(()=>{});
      }else if(msg.kind==='snapshot_logs'){
        const pre=document.getElementById('logs'); pre.textContent = (msg.lines||[]).join("\\n");
        pre.scrollTop = pre.scrollHeight;
      }
    }catch(e){}
  };
  ws.onclose = ()=> setTimeout(connectWS, 2000);
}
function startAutoRefresh(){
  if(autoRefreshHandle){
    clearInterval(autoRefreshHandle);
  }
  autoRefreshHandle = setInterval(()=>{
    loadSnapshot().catch(()=>{});
    loadTokenMeta().catch(()=>{});
  }, 5000);
}

/* ===== 집계/제한 모달 ===== */
let chartD=null, chartW=null, chartM=null;

async function openAggModal(){
  const subs = Object.keys((lastSnapshot&&lastSnapshot.tunnels)||{}).sort();
  if(!subs.length){
    showToast('집계를 볼 활성 터널이 없습니다.','warn');
    return;
  }
  const html = `
    <div class="space-y-3">
      <div class="grid-auto">
        <div class="bg-slate-50 p-3 rounded-lg">
          <div class="text-sm text-slate-600 mb-1">대상 서브도메인</div>
          <select id="aggSub" class="w-full border rounded p-2">${subs.map(s=>`<option>${s}</option>`).join('')}</select>
        </div>
        <div class="bg-slate-50 p-3 rounded-lg">
          <div class="text-sm text-slate-600 mb-1">단축 버튼 / 보기</div>
          <div class="flex gap-2 flex-wrap">
            <button id="btnLoadAgg" class="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white">집계 보기</button>
            <button id="btnSetLimit" class="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-700 text-white">제한 설정</button>
            <button id="btnViewGraph" class="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-900 text-white">그래프</button>
            <button id="btnViewTable" class="px-3 py-1.5 rounded bg-slate-600 hover:bg-slate-700 text-white">표(숫자)</button>
          </div>
        </div>
      </div>

      <div id="aggGraphs" class="grid md:grid-cols-1 gap-4">
        <div class="bg-white p-3 rounded-lg shadow">
          <div class="font-semibold mb-2">일간(최근 30)</div>
          <div style="height:220px"><canvas id="chartDaily"></canvas></div>
        </div>
        <div class="bg-white p-3 rounded-lg shadow">
          <div class="font-semibold mb-2">주간(최근 20)</div>
          <div style="height:220px"><canvas id="chartWeekly"></canvas></div>
        </div>
        <div class="bg-white p-3 rounded-lg shadow">
          <div class="font-semibold mb-2">월간(최근 12)</div>
          <div style="height:220px"><canvas id="chartMonthly"></canvas></div>
        </div>
      </div>

      <div id="aggTables" class="hidden space-y-4">
        <div class="bg-white p-3 rounded-lg shadow">
          <div class="font-semibold mb-2">일간(최근 30)</div>
          <div id="tblDaily" class="overflow-x-auto"></div>
        </div>
        <div class="bg-white p-3 rounded-lg shadow">
          <div class="font-semibold mb-2">주간(최근 20)</div>
          <div id="tblWeekly" class="overflow-x-auto"></div>
        </div>
        <div class="bg-white p-3 rounded-lg shadow">
          <div class="font-semibold mb-2">월간(최근 12)</div>
          <div id="tblMonthly" class="overflow-x-auto"></div>
        </div>
      </div>
    </div>`;
  const p = openCustomModal('대역폭 집계/제한', html, '닫기');
  document.getElementById('btnLoadAgg').onclick = ()=> renderAggCharts(document.getElementById('aggSub').value);
  document.getElementById('btnSetLimit').onclick = ()=> jumpFromModal(()=> openLimitModal(document.getElementById('aggSub').value));
  document.getElementById('btnViewGraph').onclick = ()=> { document.getElementById('aggGraphs').classList.remove('hidden'); document.getElementById('aggTables').classList.add('hidden'); };
  document.getElementById('btnViewTable').onclick = ()=> { document.getElementById('aggGraphs').classList.add('hidden'); document.getElementById('aggTables').classList.remove('hidden'); };
  if(subs.length>0) renderAggCharts(subs[0]);
  await p;
}

function makeTableHtml(rows){
  const th = `<thead class="bg-slate-100"><tr><th class="text-left p-2">기간</th><th class="text-right p-2">TX</th><th class="text-right p-2">RX</th><th class="text-right p-2">TOTAL</th></tr></thead>`;
  const tb = rows.map(r=>`<tr><td class="p-2">${escapeHtml(r.key)}</td><td class="p-2 text-right">${formatBytes(r.tx)}</td><td class="p-2 text-right">${formatBytes(r.rx)}</td><td class="p-2 text-right">${formatBytes(r.total)}</td></tr>`).join('');
  return `<table class="min-w-full text-sm border rounded">${th}<tbody>${tb}</tbody></table>`;
}

async function renderAggCharts(sub){
  const daily = await api(`/api/stats/usage?sub=${encodeURIComponent(sub)}&period=daily&limit=30`);
  const weekly= await api(`/api/stats/usage?sub=${encodeURIComponent(sub)}&period=weekly&limit=20`);
  const monthly=await api(`/api/stats/usage?sub=${encodeURIComponent(sub)}&period=monthly&limit=12`);
  const mk = (arr)=>({
    labels: arr.map(x=>x.key),
    tx: arr.map(x=>x.tx),
    rx: arr.map(x=>x.rx),
    total: arr.map(x=>x.total)
  });
  const d=mk((daily.items||[])), w=mk((weekly.items||[])), m=mk((monthly.items||[]));
  const axisOptions = {
    beginAtZero:true,
    ticks:{ callback:(value)=> formatAxisBytes(value) },
    title:{ display:true, text:'Traffic' },
  };
  const tooltipOptions = {
    callbacks:{
      label:(ctx)=> `${ctx.dataset.label}: ${formatBytes(ctx.parsed.y ?? ctx.raw ?? 0)}`
    }
  };
  const makeCfg=(lbls, tx, rx)=>({
    type:'line',
    data:{ labels: lbls, datasets:[
      {label:'TX', data: tx, tension:.25, borderColor:'#1f6b47', backgroundColor:'rgba(31,107,71,.12)', fill:true, pointRadius:3, pointHoverRadius:4},
      {label:'RX', data: rx, tension:.25, borderColor:'#b87c23', backgroundColor:'rgba(184,124,35,.14)', fill:true, pointRadius:3, pointHoverRadius:4}
    ]},
    options:{
      responsive:true,
      maintainAspectRatio:false,
      interaction:{ mode:'index', intersect:false },
      plugins:{legend:{display:true}, tooltip: tooltipOptions},
      scales:{ y: axisOptions }
    }
  });
  const makeCfg2=(lbls, tot)=>({
    type:'bar',
    data:{ labels: lbls, datasets:[{label:'TOTAL', data: tot, backgroundColor:'rgba(15,79,50,.75)', borderRadius:10}]},
    options:{
      responsive:true,
      maintainAspectRatio:false,
      plugins:{legend:{display:true}, tooltip: tooltipOptions},
      scales:{ y: axisOptions }
    }
  });

  if(chartD) chartD.destroy(); if(chartW) chartW.destroy(); if(chartM) chartM.destroy();
  const ctxD=document.getElementById('chartDaily').getContext('2d');
  const ctxW=document.getElementById('chartWeekly').getContext('2d');
  const ctxM=document.getElementById('chartMonthly').getContext('2d');
  chartD=new Chart(ctxD, makeCfg(d.labels, d.tx, d.rx));
  chartW=new Chart(ctxW, makeCfg(w.labels, w.tx, w.rx));
  chartM=new Chart(ctxM, makeCfg2(m.labels, m.total));

  document.getElementById('tblDaily').innerHTML = makeTableHtml(daily.items||[]);
  document.getElementById('tblWeekly').innerHTML = makeTableHtml(weekly.items||[]);
  document.getElementById('tblMonthly').innerHTML = makeTableHtml(monthly.items||[]);
  showToast('집계 로드 완료','ok');
}

/* 제한 모달 */
async function openLimitModal(sub){
  try{
    const cur = await api(`/api/admin/limits/${encodeURIComponent(sub)}`);
    const L = (cur&&cur.limits)||{};
    const html = `
      <div class="space-y-2">
        <div class="field-help">단위: 숫자+접미사(B/KB/MB/GB/TB). 비워두면 제한 없음.</div>
        <div class="grid-auto">
          <div class="field">
            <label for="limDaily">일간</label>
            <input id="limDaily" placeholder="예: 10GB" value="${L.daily?formatBytes(L.daily):''}">
          </div>
          <div class="field">
            <label for="limWeekly">주간</label>
            <input id="limWeekly" placeholder="예: 50GB" value="${L.weekly?formatBytes(L.weekly):''}">
          </div>
          <div class="field">
            <label for="limMonthly">월간</label>
            <input id="limMonthly" placeholder="예: 200GB" value="${L.monthly?formatBytes(L.monthly):''}">
          </div>
        </div>
      </div>`;
    const ok = await openCustomModal(`대역폭 제한 (${sub})`, html, '저장');
    if(!ok) return;
    const parseHuman = (s)=>{
      s=(s||'').trim(); if(!s) return 0;
      const m=s.match(/^(\\d+(?:\\.\\d+)?)\\s*(B|KB|MB|GB|TB)?$/i);
      if(!m) return 0;
      let v=parseFloat(m[1]); const u=(m[2]||'B').toUpperCase();
      const mul = {B:1,KB:1024,MB:1048576,GB:1073741824,TB:1099511627776}[u]||1;
      return Math.round(v*mul);
    };
    const payload = {
      daily: parseHuman(document.getElementById('limDaily').value),
      weekly: parseHuman(document.getElementById('limWeekly').value),
      monthly: parseHuman(document.getElementById('limMonthly').value),
    };
    await api(`/api/admin/limits/${encodeURIComponent(sub)}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    showToast('제한이 저장되었습니다.','ok');
  }catch(err){
    showToast(`제한 저장 실패: ${err.message}`,'err',2800);
  }
}

/* 전역 스케줄 모달(기존 편집기 재사용) */
function openScheduleModal(sub, currentItems){
  return new Promise((resolve)=>{
    const ov = document.getElementById('modalOverlay');
    document.getElementById('modalTitle').textContent = `시간대 설정 (${sub})`;
    const seed = (currentItems||[]).map(x=>`${x.days||'all'} ${x.start||'00:00'}~${x.end||'23:59'}`).join('\\n');
    document.getElementById('modalBody').innerHTML = `
      <div class="space-y-2">
        <p class="text-sm text-slate-500">한 줄에 하나씩 <b>days start~end</b> 형식으로 입력하세요.<br>예) <code>mon-fri 09:00~18:00</code></p>
        <textarea id="schEdit" class="w-full border rounded-lg p-2 h-48" placeholder="all 00:00~23:59">${seed}</textarea>
      </div>`;
    const ok = document.getElementById('modalOk');
    const no = document.getElementById('modalCancel');
    const close = () => { ov.style.display='none'; ok.onclick=null; no.onclick=null; }
    ok.onclick = ()=>{
      const raw = document.getElementById('schEdit').value.trim();
      const items = raw? raw.split(/\\n+/).map(s=>s.trim()).filter(Boolean).map(s=>{
        const m = s.match(/^(\\S+)\\s+(\\d{2}:\\d{2})~(\\d{2}:\\d{2})$/);
        if(!m) return null; return {days:m[1], start:m[2], end:m[3]};
      }).filter(Boolean) : [];
      resolve(items); close();
    };
    no.onclick = ()=>{ resolve(null); close(); }
    ov.style.display='flex';
  });
}

/* 접속 IP 모달 */
async function setTunnelIpBlockState(sub, ip, blocked){
  const path = blocked ? 'block-ip' : 'unblock-ip';
  return api(`/api/admin/clients/${encodeURIComponent(sub)}/${path}`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip}),
  });
}

function fmtDuration(ms){
  if(ms == null) return '-';
  const s = Math.max(0, Math.floor(ms/1000));
  const hh = Math.floor(s/3600), mm = Math.floor((s%3600)/60), ss = s%60;
  const pad = (n)=> n.toString().padStart(2,'0');
  if(hh>0) return `${pad(hh)}:${pad(mm)}:${pad(ss)}`;
  return `${pad(mm)}:${pad(ss)}`;
}

async function openHistoryDetailModal(sub, opts={}){
  const state = {
    date: opts.date || '',
    search: opts.search || '',
    page: 1,
    pageSize: 8,
    days: opts.days || 90,
  };
  const fetchData = async ()=>{
    const qs = new URLSearchParams({
      days: String(state.days),
      page: String(state.page),
      page_size: String(state.pageSize),
    });
    if(state.date) qs.set('date', state.date);
    if(state.search) qs.set('search', state.search);
    return api(`/api/admin/clients/${encodeURIComponent(sub)}/history?${qs.toString()}`);
  };
  let data = await fetchData();

  const renderModal = (d)=>{
    const items = d.items || [];
    return `
      <div class="modal-stack">
        <section class="panel" style="box-shadow:none">
          <div class="panel-head">
            <div>
              <h3>${state.date ? escapeHtml(state.date) : '최근 접속 검색 결과'}</h3>
              <p>${state.date ? '선택한 날짜의 접속 IP를 페이지 단위로 확인합니다.' : '최근 접속 기록에서 IP를 검색합니다.'}</p>
            </div>
          </div>
          <div class="search-inline">
            <input id="historyDetailSearch" placeholder="IP 검색" value="${escapeHtml(state.search)}"/>
            <button class="btn btn-secondary btn-mini" id="historyDetailSearchBtn">검색</button>
          </div>
          <div class="list-stack" style="margin-top:14px">
            ${items.length ? items.map(item=>`
              <div class="mapping-row">
                <div class="mapping-meta">
                  <strong>${escapeHtml(item.ip)}</strong>
                  <span>${escapeHtml(item.date)} · 기록 ${escapeHtml(item.count||0)}회 · 최근 ${escapeHtml(item.last_seen || '-')}</span>
                </div>
                <div class="ip-actions">
                  <button class="btn btn-ghost btn-mini history-session-btn" data-ip="${escapeHtml(item.ip)}">세션 상세</button>
                  <button class="btn ${(lastSnapshot && lastSnapshot.tunnels && lastSnapshot.tunnels[sub] && (lastSnapshot.tunnels[sub].blocked_ips||[]).includes(item.ip)) ? 'btn-secondary history-unblock-btn' : 'btn-danger history-block-btn'} btn-mini" data-ip="${escapeHtml(item.ip)}">
                    ${(lastSnapshot && lastSnapshot.tunnels && lastSnapshot.tunnels[sub] && (lastSnapshot.tunnels[sub].blocked_ips||[]).includes(item.ip)) ? '차단 해제' : '즉시 차단'}
                  </button>
                </div>
              </div>
            `).join('') : '<div class="empty-state">조건에 맞는 접속 기록이 없습니다.</div>'}
          </div>
          ${renderPager(d.page || 1, d.pages || 1)}
        </section>
      </div>`;
  };

  const bindActions = ()=>{
    const body = document.getElementById('modalBody');
    const searchBtn = body.querySelector('#historyDetailSearchBtn');
    const searchInput = body.querySelector('#historyDetailSearch');
    if(searchBtn){
      searchBtn.onclick = async ()=>{
        state.search = (searchInput.value || '').trim();
        state.page = 1;
        data = await fetchData();
        body.innerHTML = renderModal(data);
        bindActions();
      };
    }
    body.querySelectorAll('[data-page-nav]').forEach(btn=>{
      btn.onclick = async ()=>{
        const dir = btn.getAttribute('data-page-nav');
        const nextPage = dir === 'prev' ? Math.max(1, (data.page||1) - 1) : Math.min(data.pages||1, (data.page||1) + 1);
        if(nextPage === state.page) return;
        state.page = nextPage;
        data = await fetchData();
        body.innerHTML = renderModal(data);
        bindActions();
      };
    });
    body.querySelectorAll('.history-session-btn').forEach(btn=>{
      btn.onclick = ()=> jumpFromModal(()=> openIpSessions(sub, btn.getAttribute('data-ip')));
    });
    body.querySelectorAll('.history-block-btn').forEach(btn=>{
      btn.onclick = async ()=>{
        const ip = btn.getAttribute('data-ip');
        const ok = await confirmAsync(`${escapeHtml(ip)} 를 차단하고 현재 연결을 즉시 종료할까요?`);
        if(!ok) return;
        try{
          await setTunnelIpBlockState(sub, ip, true);
          await loadSnapshot();
          data = await fetchData();
          body.innerHTML = renderModal(data);
          bindActions();
          showToast(`${ip} 를 차단했습니다.`,'ok');
        }catch(err){
          showToast(`IP 차단 실패: ${err.message}`,'err',2800);
        }
      };
    });
    body.querySelectorAll('.history-unblock-btn').forEach(btn=>{
      btn.onclick = async ()=>{
        const ip = btn.getAttribute('data-ip');
        try{
          await setTunnelIpBlockState(sub, ip, false);
          await loadSnapshot();
          data = await fetchData();
          body.innerHTML = renderModal(data);
          bindActions();
          showToast(`${ip} 차단을 해제했습니다.`,'ok');
        }catch(err){
          showToast(`차단 해제 실패: ${err.message}`,'err',2800);
        }
      };
    });
  };

  const title = state.date ? `접속 기록 (${sub} / ${state.date})` : `접속 기록 검색 (${sub})`;
  const p = openCustomModal(title, renderModal(data), '닫기');
  bindActions();
  await p;
}

async function openClientsModal(sub){
  const fetchData = ()=> api(`/api/admin/clients/${encodeURIComponent(sub)}?days=90`);
  let data = await fetchData();
  const state = {blockedPage:1, blockedQuery:''};

  const monthKeys = ()=>{
    const keys = Array.from(new Set((data.history_dates||[]).map(item=> String(item.date || '').slice(0, 7)).filter(Boolean))).sort().reverse();
    return keys.length ? keys : [monthKeyFromDate(new Date())];
  };
  let currentMonth = monthKeys()[0];

  const renderCurrentRow = (ip, blocked)=>`
    <div class="mapping-row">
      <div class="mapping-meta">
        <strong>${escapeHtml(ip)}</strong>
        <span>현재 이 터널에 연결 중인 IP</span>
      </div>
      <div class="ip-actions">
        <button class="btn btn-ghost btn-mini current-session-btn" data-ip="${escapeHtml(ip)}">세션 상세</button>
        ${blocked
          ? `<button class="btn btn-secondary btn-mini current-unblock-btn" data-ip="${escapeHtml(ip)}">차단 해제</button>`
          : `<button class="btn btn-danger btn-mini current-block-btn" data-ip="${escapeHtml(ip)}">즉시 차단</button>`
        }
      </div>
    </div>`;

  const renderCalendar = ()=>{
    const entries = (data.history_dates || []).slice().sort((a,b)=> String(b.date).localeCompare(String(a.date)));
    const availableMonths = monthKeys();
    if(!availableMonths.includes(currentMonth)){
      currentMonth = availableMonths[0];
    }
    const dayMap = Object.fromEntries(entries.map(item=> [item.date, item.count || 0]));
    const base = parseMonthKey(currentMonth);
    const year = base.getFullYear();
    const month = base.getMonth();
    const firstDay = new Date(year, month, 1);
    const totalDays = new Date(year, month + 1, 0).getDate();
    const cells = [];
    for(let idx=0; idx<firstDay.getDay(); idx+=1){
      cells.push('<div class="calendar-empty"></div>');
    }
    for(let day=1; day<=totalDays; day+=1){
      const dateKey = `${year}-${String(month+1).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
      const count = Number(dayMap[dateKey] || 0);
      if(count > 0){
        cells.push(`
          <div class="calendar-cell">
            <button class="calendar-day has-data history-date-btn" data-date="${dateKey}">
              <span>${day}</span>
              <span class="count">${count} IP</span>
            </button>
          </div>`);
      }else{
        cells.push(`
          <div class="calendar-cell">
            <div class="calendar-day disabled">
              <span>${day}</span>
              <span class="subtle">기록 없음</span>
            </div>
          </div>`);
      }
    }
    while(cells.length % 7){
      cells.push('<div class="calendar-empty"></div>');
    }
    const monthIndex = availableMonths.indexOf(currentMonth);
    return `
      <div class="calendar-shell">
        <div class="calendar-head">
          <div class="session-meta">
            <span class="pill">${formatMonthLabel(currentMonth)}</span>
            <span class="pill">기록 일수 ${(data.history_dates||[]).length}</span>
          </div>
          <div class="ip-actions">
            <button class="btn btn-ghost btn-mini month-nav-btn" data-month-nav="prev" ${monthIndex >= availableMonths.length - 1 ? 'disabled' : ''}>이전 달</button>
            <button class="btn btn-ghost btn-mini month-nav-btn" data-month-nav="next" ${monthIndex <= 0 ? 'disabled' : ''}>다음 달</button>
          </div>
        </div>
        <div class="calendar-grid">
          <div class="calendar-weekday">Sun</div>
          <div class="calendar-weekday">Mon</div>
          <div class="calendar-weekday">Tue</div>
          <div class="calendar-weekday">Wed</div>
          <div class="calendar-weekday">Thu</div>
          <div class="calendar-weekday">Fri</div>
          <div class="calendar-weekday">Sat</div>
          ${cells.join('')}
        </div>
      </div>`;
  };

  const renderBlockedList = ()=>{
    const blocked = (data.blocked_ips || []).slice().sort();
    const filtered = blocked.filter(ip=> !state.blockedQuery || ip.toLowerCase().includes(state.blockedQuery.toLowerCase()));
    const pageSize = 6;
    const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
    const page = Math.max(1, Math.min(pages, state.blockedPage));
    state.blockedPage = page;
    const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize);
    return `
      <div class="search-inline" style="margin-bottom:14px">
        <input id="blockedSearch" placeholder="차단 IP 검색" value="${escapeHtml(state.blockedQuery)}"/>
        <button class="btn btn-secondary btn-mini" id="blockedSearchBtn">검색</button>
      </div>
      <div class="list-stack">
        ${pageItems.length ? pageItems.map(ip=>`
          <div class="mapping-row">
            <div class="mapping-meta">
              <strong>${escapeHtml(ip)}</strong>
              <span>이 터널 전용 차단 규칙</span>
            </div>
            <div class="ip-actions">
              <button class="btn btn-ghost btn-mini blocked-session-btn" data-ip="${escapeHtml(ip)}">세션 상세</button>
              <button class="btn btn-secondary btn-mini blocked-unblock-btn" data-ip="${escapeHtml(ip)}">차단 해제</button>
            </div>
          </div>
        `).join('') : '<div class="empty-state">차단된 IP가 없습니다.</div>'}
      </div>
      ${renderPager(page, pages)}`;
  };

  const renderModal = ()=>{
    const currentIps = data.current_ips || [];
    const blockedIps = new Set(data.blocked_ips || []);
    return `<div class="section-stack">
      <section class="panel" style="box-shadow:none">
        <div class="panel-head">
          <div>
            <h3>현재 접속 중 IP</h3>
            <p>차단하면 해당 IP의 현재 TCP/UDP 연결을 즉시 종료합니다.</p>
          </div>
        </div>
        <div class="list-stack">${currentIps.length ? currentIps.map(ip=> renderCurrentRow(ip, blockedIps.has(ip))).join('') : '<div class="empty-state">현재 접속 중인 IP가 없습니다.</div>'}</div>
      </section>
      <section class="panel" style="box-shadow:none">
        <div class="panel-head">
          <div>
            <h3>최근 접속 히스토리</h3>
            <p>날짜를 선택하면 해당 날짜의 접속 IP 목록을 별도 모달에서 페이지 단위로 확인합니다.</p>
          </div>
        </div>
        <div class="search-inline" style="margin-bottom:14px">
          <input id="historySearch" placeholder="최근 접속 IP 검색" value=""/>
          <button class="btn btn-secondary btn-mini" id="historySearchBtn">검색</button>
        </div>
        ${(data.history_dates||[]).length ? renderCalendar() : '<div class="empty-state">최근 접속 히스토리가 없습니다.</div>'}
      </section>
      <section class="panel" style="box-shadow:none">
        <div class="panel-head">
          <div>
            <h3>현재 차단 목록</h3>
            <p>검색과 페이지 이동으로 길어진 차단 목록을 정리해서 확인합니다.</p>
          </div>
        </div>
        ${renderBlockedList()}
      </section>
    </div>`;
  };

  const rerender = ()=>{
    document.getElementById('modalBody').innerHTML = renderModal();
    bindActions();
  };

  const bindActions = ()=>{
    const body = document.getElementById('modalBody');
    body.querySelectorAll('.current-session-btn,.blocked-session-btn').forEach(btn=>{
      btn.onclick = ()=> jumpFromModal(()=> openIpSessions(sub, btn.getAttribute('data-ip')));
    });
    body.querySelectorAll('.current-block-btn').forEach(btn=>{
      btn.onclick = async ()=>{
        const ip = btn.getAttribute('data-ip');
        const ok = await confirmAsync(`${escapeHtml(ip)} 를 차단하고 현재 연결을 즉시 종료할까요?`);
        if(!ok) return;
        try{
          await setTunnelIpBlockState(sub, ip, true);
          await loadSnapshot();
          data = await fetchData();
          rerender();
          showToast(`${ip} 를 차단했습니다.`,'ok');
        }catch(err){
          showToast(`IP 차단 실패: ${err.message}`,'err',2800);
        }
      };
    });
    body.querySelectorAll('.current-unblock-btn,.blocked-unblock-btn').forEach(btn=>{
      btn.onclick = async ()=>{
        const ip = btn.getAttribute('data-ip');
        try{
          await setTunnelIpBlockState(sub, ip, false);
          await loadSnapshot();
          data = await fetchData();
          rerender();
          showToast(`${ip} 차단을 해제했습니다.`,'ok');
        }catch(err){
          showToast(`차단 해제 실패: ${err.message}`,'err',2800);
        }
      };
    });
    body.querySelectorAll('.history-date-btn').forEach(btn=>{
      btn.onclick = ()=> jumpFromModal(()=> openHistoryDetailModal(sub, {date: btn.getAttribute('data-date')}));
    });
    body.querySelectorAll('.month-nav-btn').forEach(btn=>{
      btn.onclick = ()=>{
        const months = monthKeys();
        const idx = months.indexOf(currentMonth);
        if(btn.getAttribute('data-month-nav') === 'prev'){
          currentMonth = months[Math.min(months.length - 1, idx + 1)] || currentMonth;
        }else{
          currentMonth = months[Math.max(0, idx - 1)] || currentMonth;
        }
        rerender();
      };
    });
    const historySearchBtn = body.querySelector('#historySearchBtn');
    if(historySearchBtn){
      historySearchBtn.onclick = ()=>{
        const value = (body.querySelector('#historySearch').value || '').trim();
        if(!value){
          showToast('검색할 IP를 입력하세요.','warn');
          return;
        }
        jumpFromModal(()=> openHistoryDetailModal(sub, {search:value}));
      };
    }
    const blockedSearchBtn = body.querySelector('#blockedSearchBtn');
    if(blockedSearchBtn){
      blockedSearchBtn.onclick = ()=>{
        state.blockedQuery = (body.querySelector('#blockedSearch').value || '').trim();
        state.blockedPage = 1;
        rerender();
      };
    }
    body.querySelectorAll('[data-page-nav]').forEach(btn=>{
      btn.onclick = ()=>{
        const dir = btn.getAttribute('data-page-nav');
        const blocked = (data.blocked_ips || []).filter(ip=> !state.blockedQuery || ip.toLowerCase().includes(state.blockedQuery.toLowerCase()));
        const pages = Math.max(1, Math.ceil(blocked.length / 6));
        state.blockedPage = dir === 'prev' ? Math.max(1, state.blockedPage - 1) : Math.min(pages, state.blockedPage + 1);
        rerender();
      };
    });
  };

  const p = openCustomModal(`접속 IP (${sub})`, renderModal(), '닫기');
  bindActions();
  await p;
}

async function openIpSessions(sub, ip){
  const days = 90;
  const d = await api(`/api/admin/clients/${encodeURIComponent(sub)}/sessions?ip=${encodeURIComponent(ip)}&days=${days}`);
  const rows = [];
  (d.sessions||[]).forEach(day=>{
    (day.items||[]).forEach(sess=>{
      rows.push({
        date: day.date,
        start: sess.start || '',
        end: sess.end || '',
        proto: String(sess.proto || '').toUpperCase(),
        mapping: sess.mapping || '',
        remotePort: sess.remote_port || '',
      });
    });
  });
  rows.sort((a,b)=> (b.date+b.start).localeCompare(a.date+a.start));

  const now = new Date();
  const tr = rows.map(r=>{
    const st = r.start ? new Date(r.start) : null;
    const en = r.end ? new Date(r.end) : null;
    const dur = (st && en) ? (en - st) : (st ? (now - st) : null);
    const td = (x, align='left')=> `<td style="padding:10px 12px;text-align:${align}">${x || '-'}</td>`;
    const mapping = [r.proto, r.mapping].filter(Boolean).join(' / ') || '-';
    return `<tr>
      ${td(r.date)}
      ${td(r.start ? r.start.replace('T',' ').replace('Z',' UTC') : '')}
      ${td(r.end ? r.end.replace('T',' ').replace('Z',' UTC') : '')}
      ${td(mapping)}
      ${td(r.remotePort ? String(r.remotePort) : '-')}
      ${td(fmtDuration(dur), 'right')}
    </tr>`;
  }).join('');

  const html = `<div class="space-y-2">
    <div class="field-help">IP: <b>${escapeHtml(ip)}</b> · 최근 ${days}일</div>
    <div class="overflow-x-auto">
      <table class="bw-table">
        <thead>
          <tr><th>날짜(UTC)</th><th>접속시간</th><th>나간시간</th><th>포트 매핑</th><th>원격 포트</th><th style="text-align:right">지속</th></tr>
        </thead>
        <tbody>${tr || `<tr><td colspan="6" style="padding:10px 12px"><span class="subtle">세션이 없습니다.</span></td></tr>`}</tbody>
      </table>
    </div>
  </div>`;
  await openCustomModal(`세션 상세 (${sub} / ${ip})`, html, '닫기');
}

async function openPortManageModal(sub){
  const renderItems = (items, proto)=>{
    if(!items.length) return `<div class="empty-state">${proto.toUpperCase()} 포트가 없습니다.</div>`;
    return `<div class="mapping-list">${items.map(item=>`
      <div class="mapping-row">
        <div class="mapping-meta">
          <strong>${escapeHtml(item.name)}</strong>
          <span>${proto.toUpperCase()} ${escapeHtml(item.remote_port)} · ${item.managed ? '서버 등록 포트' : '클라이언트 등록 포트'}</span>
        </div>
        <div class="ip-actions">
          <span class="source-tag ${item.managed ? 'server' : 'client'}">${item.managed ? 'server' : 'client'}</span>
          <button class="btn btn-danger btn-mini delete-map-btn" data-proto="${proto}" data-name="${escapeHtml(item.name)}">삭제</button>
        </div>
      </div>
    `).join('')}</div>`;
  };

  const renderModal = ()=>{
    const tunnel = ((lastSnapshot&&lastSnapshot.tunnels)||{})[sub];
    if(!tunnel){
      return `<div class="empty-state">클라이언트 연결이 끊어져 포트 관리를 계속할 수 없습니다.</div>`;
    }
    const suppressed = [
      ...(tunnel.suppressed_tcp||[]).map(name=>`TCP ${name}`),
      ...(tunnel.suppressed_udp||[]).map(name=>`UDP ${name}`),
    ];
    return `
      <div class="modal-stack">
        <section class="panel" style="box-shadow:none">
          <div class="panel-head">
            <div>
              <h3>실시간 포트 관리</h3>
              <p>추가 또는 삭제하면 연결 중인 클라이언트에 즉시 전달되고, 재연결 이후에도 서버 상태가 유지됩니다.</p>
            </div>
          </div>
          ${suppressed.length ? `<div class="field-help" style="margin-bottom:14px">삭제 후 숨김 유지 중인 클라이언트 포트: ${escapeHtml(suppressed.join(', '))}</div>` : ''}
          <div class="grid-auto">
            <div class="mapping-block">
              <h4>TCP 포트</h4>
              ${renderItems(tunnel.tcp_items||[], 'tcp')}
            </div>
            <div class="mapping-block">
              <h4>UDP 포트</h4>
              ${renderItems(tunnel.udp_items||[], 'udp')}
            </div>
          </div>
        </section>
        <section class="panel" style="box-shadow:none">
          <div class="panel-head">
            <div>
              <h3>새 포트 추가</h3>
              <p>클라이언트 내부 대상과 서버 공개 포트를 함께 등록합니다.</p>
            </div>
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="mapProto">프로토콜</label>
              <select id="mapProto">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </div>
            <div class="field">
              <label for="mapName">매핑 이름</label>
              <input id="mapName" placeholder="예: ssh2"/>
            </div>
            <div class="field">
              <label for="mapHost">클라이언트 내부 호스트</label>
              <input id="mapHost" placeholder="예: 127.0.0.1"/>
            </div>
            <div class="field">
              <label for="mapPort">클라이언트 내부 포트</label>
              <input id="mapPort" type="number" min="1" max="65535" placeholder="예: 22"/>
            </div>
            <div class="field">
              <label for="mapRemotePort">서버 공개 포트(선택)</label>
              <input id="mapRemotePort" type="number" min="0" max="65535" placeholder="비워두면 자동 할당"/>
            </div>
            <div class="field">
              <label>안내</label>
              <div class="field-help">삭제는 현재 클라이언트에도 제거 명령을 보내고, 추가는 즉시 새 리스너를 연결합니다.</div>
            </div>
          </div>
          <div class="panel-actions" style="margin-top:14px">
            <button id="addPortBtn" class="btn btn-primary btn-mini">포트 추가</button>
          </div>
        </section>
      </div>`;
  };

  const bindActions = ()=>{
    const body = document.getElementById('modalBody');
    body.querySelectorAll('.delete-map-btn').forEach(btn=>{
      btn.onclick = async ()=>{
        const proto = btn.getAttribute('data-proto');
        const name = btn.getAttribute('data-name');
        const ok = await confirmAsync(`${escapeHtml(name)} ${proto.toUpperCase()} 포트를 삭제할까요?<br><br>현재 연결된 클라이언트에도 즉시 제거 명령을 보냅니다.`);
        if(!ok) return;
        try{
          const result = await api(`/api/tunnels/${encodeURIComponent(sub)}/mappings/${encodeURIComponent(proto)}/${encodeURIComponent(name)}`, {
            method:'DELETE',
          });
          await loadSnapshot();
          document.getElementById('modalBody').innerHTML = renderModal();
          bindActions();
          showToast(`${proto.toUpperCase()} 포트를 삭제했습니다.${result.client_notified ? ' 클라이언트에도 반영했습니다.' : ''}`,'ok');
        }catch(err){
          showToast(`포트 삭제 실패: ${err.message}`,'err',2800);
        }
      };
    });
    const addBtn = document.getElementById('addPortBtn');
    if(addBtn){
      addBtn.onclick = async ()=>{
        const payload = {
          proto: document.getElementById('mapProto').value,
          name: document.getElementById('mapName').value.trim(),
          host: document.getElementById('mapHost').value.trim(),
          port: Number(document.getElementById('mapPort').value || 0),
          remote_port: Number(document.getElementById('mapRemotePort').value || 0),
        };
        try{
          const res = await api(`/api/tunnels/${encodeURIComponent(sub)}/mappings`, {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(payload),
          });
          await loadSnapshot();
          document.getElementById('modalBody').innerHTML = renderModal();
          bindActions();
          showToast(`${payload.proto.toUpperCase()} 포트 ${res.mapping.remote_port} 추가 완료`,'ok');
        }catch(err){
          showToast(`포트 추가 실패: ${err.message}`,'err',2800);
        }
      };
    }
  };

  const p = openCustomModal(`포트 관리 (${sub})`, renderModal(), '닫기');
  bindActions();
  await p;
}

/* ===== 전역 스케줄 저장 버튼 동작 ===== */
document.getElementById('saveSch').onclick = async ()=>{
  try{
    const snap = await api('/api/tunnels');
    const cur = (snap && snap.access_schedules) || [];
    const items = await openScheduleModal('GLOBAL', cur);
    if(items===null) return;
    await api('/api/admin/schedule', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(items)});
    await renderGlobalScheduleList();
    showToast('전역 시간대가 저장되었습니다.','ok');
  }catch(err){
    showToast(`전역 시간대 저장 실패: ${err.message}`,'err',2800);
  }
};

/* 초기/기타 액션 */
document.getElementById('refreshBtn').onclick = ()=>{ loadSnapshot(); showToast('새로고침 완료','ok'); };
document.getElementById('prevLogsBtn').onclick = loadLogListAndOpenFirst;
document.getElementById('openAgg').onclick = openAggModal;
document.querySelectorAll('.rail-link').forEach(link=>{
  link.onclick = ()=> switchSection(link.dataset.section || 'overviewSection');
});

document.getElementById('loadSel').onclick = async ()=>{
  const name = document.getElementById('logSel').value;
  if(!name) return showToast('선택된 로그가 없습니다.','warn');
  try{
    const result = await api('/api/logs/get?fmt=json&mode=tail&lines=900&name='+encodeURIComponent(name));
    const pre=document.getElementById('logs');
    pre.textContent = (result.truncated ? `[tail preview] ${formatLogMeta(result.meta)}\n\n` : '') + (result.text || '');
    pre.scrollTop = pre.scrollHeight;
    showToast('로그 로드 완료','ok');
  }catch(err){
    showToast(`로그 로드 실패: ${err.message}`,'err',2800);
  }
};
document.getElementById('saveIp').onclick = async ()=>{
  const raw=document.getElementById('ipAllow').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  try{
    await api('/api/admin/ip-allow', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({allow:arr})});
    showToast('접근 허용 목록을 저장했습니다.','ok');
  }catch(err){
    showToast(`허용 목록 저장 실패: ${err.message}`,'err',2800);
  }
};
document.getElementById('saveTok').onclick = async ()=>{
  const raw=document.getElementById('tokens').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  try{
    await api('/api/admin/tokens', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({tokens:arr})});
    await loadSnapshot();
    await loadTokenMeta();
    showToast('토큰 목록을 저장했습니다.','ok');
  }catch(err){
    showToast(`토큰 저장 실패: ${err.message}`,'err',2800);
  }
};
document.getElementById('saveDeny').onclick = async ()=>{
  const raw=document.getElementById('denyIp').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  try{
    await api('/api/admin/tunnel-ip-deny', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({deny:arr})});
    await loadSnapshot();
    showToast('전역 차단 규칙을 저장했습니다.','ok');
  }catch(err){
    showToast(`전역 차단 저장 실패: ${err.message}`,'err',2800);
  }
};
document.getElementById('saveBot').onclick = async ()=>{
  const payload = {
    enabled: document.getElementById('botBlockEnabled').checked,
    block_empty_ua: document.getElementById('botBlockEmptyUa').checked,
    rules: document.getElementById('botRules').value.split(/\\n+/).map(s=>s.trim()).filter(Boolean),
  };
  try{
    await api('/api/admin/bot-blocking', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    await loadSnapshot();
    showToast('봇 차단 정책을 저장했습니다.','ok');
  }catch(err){
    showToast(`봇 차단 저장 실패: ${err.message}`,'err',2800);
  }
};
document.getElementById('clearLog').onclick = async ()=>{
  try{
    await api('/api/admin/logs/clear', {method:'POST'});
    document.getElementById('logs').textContent = '';
    showToast('실시간 로그를 비웠습니다.','ok');
  }catch(err){
    showToast(`로그 초기화 실패: ${err.message}`,'err',2800);
  }
};

/* 초기 로드 */
switchSection('overviewSection');
renderBandwidthTable();
loadSnapshot();
loadLogList();
loadTokenMeta();
connectWS();
startAutoRefresh();
</script>
</body></html>
"""

@web.middleware
async def admin_ip_mw(request, handler):
    if request.path.startswith("/dashboard") or request.path.startswith("/api/") or request.path=="/admin_ws":
        ring_log(f"ADMIN access {request_ip_label(request)} {request.method} {request.path}")
    return await handler(request)

# ----- 로그인/로그아웃 -----
async def logout(request: web.Request) -> web.Response:
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if token:
        ADMIN_SESSIONS.pop(token, None)
    resp = web.HTTPFound("/login")
    resp.del_cookie(ADMIN_SESSION_COOKIE, path="/")
    return resp

async def login(request: web.Request) -> web.Response:
    if not ip_allowed(client_ip(request)):
        return web.Response(status=403, text="Forbidden by IP allowlist")
    if admin_authenticated(request):
        raise web.HTTPFound("/dashboard")
    return web.Response(text=LOGIN_HTML, content_type="text/html")

async def api_login(request: web.Request) -> web.Response:
    if not ip_allowed(client_ip(request)):
        return web.json_response({"ok":False, "reason":"forbidden_by_ip"}, status=403)
    if not ADMIN_USER or not ADMIN_PASS:
        return web.json_response({"ok":False, "reason":"admin_not_configured"}, status=500)
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if username != ADMIN_USER or password != ADMIN_PASS:
        return web.json_response({"ok":False, "reason":"invalid_credentials"}, status=401)
    token = create_admin_session()
    resp = web.json_response({"ok":True, "redirect":"/dashboard"})
    resp.set_cookie(
        ADMIN_SESSION_COOKIE,
        token,
        max_age=ADMIN_SESSION_TTL,
        httponly=True,
        samesite="Lax",
        secure=request.secure,
        path="/",
    )
    return resp

@require_admin
async def dashboard_page(request: web.Request) -> web.Response:
    return web.Response(text=DASH_HTML, content_type="text/html")

@require_admin
async def admin_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=15.0)
    await ws.prepare(request)
    ADMIN_WSS.append(ws)
    await ws.send_json({"kind":"snapshot_logs","lines": list(LOG_RING)})
    try:
        async for _ in ws: pass
    finally:
        with contextlib.suppress(ValueError):
            ADMIN_WSS.remove(ws)
    return ws

# ====== 관리 API ======
@require_admin
async def api_tunnels(request: web.Request) -> web.Response:
    return web.json_response({
        "ok": True,
        "range": f"TCP {TCP_START}-{TCP_END} / UDP {UDP_START}-{UDP_END}",
        "admin_ip_allow": STATE.get("admin_ip_allow", []),
        "access_schedules": STATE.get("access_schedules", []),
        "bot_blocking": normalized_bot_blocking(STATE.get("bot_blocking")),
        "tokens": list(ALLOWED_TOKENS),
        "tunnel_ip_deny": STATE.get("tunnel_ip_deny", []),
        "server_time": datetime.datetime.now().replace(microsecond=0).isoformat(),
        "tunnels": {
            k:{
                "tcp":{n:v["port"] for n,v in TUNNELS[k].get("tcp",{}).items()},
                "udp":{n:v["port"] for n,v in TUNNELS[k].get("udp",{}).items()},
                "tcp_items": sorted([
                    {"name":n, "remote_port":v["port"], "managed":bool(v.get("managed"))}
                    for n,v in TUNNELS[k].get("tcp",{}).items()
                ], key=lambda item: item["name"]),
                "udp_items": sorted([
                    {"name":n, "remote_port":v["port"], "managed":bool(v.get("managed"))}
                    for n,v in TUNNELS[k].get("udp",{}).items()
                ], key=lambda item: item["name"]),
                "tcp_streams": sum(len(v["streams"]) for v in TUNNELS[k].get("tcp",{}).values()),
                "udp_flows":   sum(len(v["flows"]) for v in TUNNELS[k].get("udp",{}).values()),
                "current_ips": _current_ips_for(k),
                "blocked_ips": ((STATE.get("per_tunnel_ip_deny") or {}).get(k, []) or []),
                "connected_at": TUNNELS[k].get("connected_at"),
                "peer_ip": TUNNELS[k].get("peer_ip"),
                "managed_tcp": sorted([n for n,v in TUNNELS[k].get("tcp",{}).items() if v.get("managed")]),
                "managed_udp": sorted([n for n,v in TUNNELS[k].get("udp",{}).items() if v.get("managed")]),
                "suppressed_tcp": suppressed_mapping_bucket(k).get("tcp", []),
                "suppressed_udp": suppressed_mapping_bucket(k).get("udp", []),
            } for k in TUNNELS.keys()
        }
    })

@require_admin
async def api_disconnect(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    ok, reason = await send_control_and_wait(sub, "disconnect", timeout=5.0)
    if ok:
        ring_log(f"ADMIN disconnected client {sub}")
        broadcast_refresh()
    return web.json_response({"ok":ok, "reason":reason or ("tunnel_offline" if not ok else "")})

@require_admin
async def api_reconnect(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    ok, reason = await send_control_and_wait(sub, "restart", timeout=8.0)
    if ok:
        ring_log(f"ADMIN restarted client {sub}")
        broadcast_refresh()
    return web.json_response({"ok":ok, "reason":reason or ("tunnel_offline" if not ok else "")})

@require_admin
async def api_set_ip_allow(request: web.Request) -> web.Response:
    body = await request.json()
    allow = body.get("allow") or []
    STATE["admin_ip_allow"] = allow
    save_state(STATE)
    return web.json_response({"ok":True,"admin_ip_allow":allow})

@require_admin
async def api_set_tokens(request: web.Request) -> web.Response:
    global ALLOWED_TOKENS
    body = await request.json()
    toks = [t.strip() for t in (body.get("tokens") or []) if t.strip()]
    os.makedirs(os.path.dirname(TOK_FILE), exist_ok=True)
    with open(TOK_FILE,"w",encoding="utf-8") as f:
        f.write(",".join(toks))
    ALLOWED_TOKENS = set(load_tokens())
    STATE["revoked_tokens"] = [token for token in (STATE.get("revoked_tokens", []) or []) if token not in ALLOWED_TOKENS]
    save_state(STATE)
    ring_log(f"ADMIN updated tokens: {len(ALLOWED_TOKENS)} tokens")
    broadcast({"kind":"log","line":"[ADMIN] tokens updated"})
    return web.json_response({"ok":True,"tokens":list(ALLOWED_TOKENS)})

@require_admin
async def api_token_meta(request: web.Request) -> web.Response:
    items=[]
    meta = STATE.get("token_meta", {})
    keys = sorted(set(ALLOWED_TOKENS) | set(meta.keys()))
    for tk in keys:
        m = meta.get(tk, {})
        items.append({"token": tk, "last_ip": m.get("last_ip"), "last_at": m.get("last_at")})
    return web.json_response({"ok":True,"items":items})

@require_admin
async def api_token_revoke(request: web.Request) -> web.Response:
    global ALLOWED_TOKENS
    body = await request.json()
    token = (body.get("token") or "").strip()
    if not token: return web.json_response({"ok":False,"reason":"no token"})
    if token in ALLOWED_TOKENS or token in (STATE.get("revoked_tokens", []) or []):
        ALLOWED_TOKENS.discard(token)
        revoked = [item for item in (STATE.get("revoked_tokens", []) or []) if item != token]
        revoked.append(token)
        STATE["revoked_tokens"] = sorted(dict.fromkeys(revoked))
        with open(TOK_FILE,"w",encoding="utf-8") as f:
            f.write(",".join(sorted(ALLOWED_TOKENS)))
        disconnected = []
        for sub, info in list(TUNNELS.items()):
            if info.get("auth_token") != token:
                continue
            disconnected.append(sub)
            with contextlib.suppress(Exception):
                await info["ws"].close(message=b"token_revoked")
        save_state(STATE)
        ring_log(f"ADMIN revoked token: {token} disconnected={len(disconnected)}")
        broadcast({"kind":"log","line":f"[ADMIN] token revoked: {token}"})
        broadcast_refresh()
        return web.json_response({"ok":True, "token":token, "disconnected":disconnected})
    return web.json_response({"ok":False,"reason":"not found"})

@require_admin
async def api_logs_clear(request: web.Request) -> web.Response:
    LOG_RING.clear()
    return web.json_response({"ok":True})

@require_admin
async def api_schedule_set(request: web.Request) -> web.Response:
    body = await request.json()
    items = body if isinstance(body,list) else body.get("items") or body.get("schedules") or []
    norm=[]
    def _ok(hm:str)->bool:
        try:
            h,m = [int(x) for x in hm.split(":")]
            return 0<=h<24 and 0<=m<60
        except: return False
    for it in items:
        d=(it.get("days") or "all").strip() or "all"
        s=(it.get("start") or "00:00").strip() or "00:00"
        e=(it.get("end") or "23:59").strip() or "23:59"
        if not _ok(s) or not _ok(e): continue
        norm.append({"days":d,"start":s,"end":e})
    STATE["access_schedules"]=norm
    save_state(STATE)
    ring_log(f"ADMIN updated schedule: {len(norm)} rules")
    broadcast({"kind":"log","line":"[ADMIN] schedule updated"})
    return web.json_response({"ok":True,"items":norm})

@require_admin
async def api_tunnel_schedule_get(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    items = (STATE.get("per_tunnel_schedules") or {}).get(sub, [])
    return web.json_response({"ok": True, "sub": sub, "items": items})

@require_admin
async def api_tunnel_schedule_set(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    body = await request.json()
    items = body if isinstance(body, list) else body.get("items", [])
    norm=[]
    def _ok(hm:str)->bool:
        try:
            h,m = [int(x) for x in hm.split(":")]
            return 0<=h<24 and 0<=m<60
        except: return False
    for it in items:
        d=(it.get("days") or "all").strip() or "all"
        s=(it.get("start") or "00:00").strip() or "00:00"
        e=(it.get("end") or "23:59").strip() or "23:59"
        if not _ok(s) or not _ok(e): continue
        norm.append({"days":d,"start":s,"end":e})
    STATE.setdefault("per_tunnel_schedules", {})[sub] = norm
    save_state(STATE)
    ring_log(f"ADMIN set per-tunnel schedule for {sub}: {len(norm)} rules")
    broadcast({"kind":"log","line":f"[ADMIN] schedule set for {sub}"})
    return web.json_response({"ok":True,"sub":sub,"items":norm})

@require_admin
async def api_set_tunnel_deny(request: web.Request) -> web.Response:
    body = await request.json()
    deny = [x.strip() for x in (body.get("deny") or []) if x.strip()]
    STATE["tunnel_ip_deny"] = deny
    save_state(STATE)
    await disconnect_blocked_ips()
    ring_log(f"ADMIN updated tunnel deny IPs: {len(deny)} items")
    broadcast({"kind":"log","line":"[ADMIN] tunnel deny updated"})
    broadcast_refresh()
    return web.json_response({"ok":True,"deny":deny})

@require_admin
async def api_set_bot_blocking(request: web.Request) -> web.Response:
    body = await request.json()
    cfg = normalized_bot_blocking({
        "enabled": body.get("enabled", True),
        "block_empty_ua": body.get("block_empty_ua", True),
        "rules": body.get("rules") or [],
    })
    STATE["bot_blocking"] = cfg
    save_state(STATE)
    ring_log(f"ADMIN updated bot blocking: enabled={cfg['enabled']} rules={len(cfg['rules'])} empty_ua={cfg['block_empty_ua']}")
    broadcast_refresh()
    return web.json_response({"ok":True, "bot_blocking":cfg})

# ===== 집계 API =====
@require_admin
async def api_usage(request: web.Request) -> web.Response:
    sub = request.query.get("sub","").strip()
    period = request.query.get("period","daily").strip()
    limit = int(request.query.get("limit","30"))
    if not sub: return web.json_response({"ok":False,"reason":"no sub"}, status=400)
    if period not in ("daily","weekly","monthly"): return web.json_response({"ok":False,"reason":"bad period"}, status=400)
    items = _get_usage_slice(sub, period, limit)
    return web.json_response({"ok":True,"items":items})

@require_admin
async def api_usage_all(request: web.Request) -> web.Response:
    sub = request.query.get("sub","").strip()
    if not sub: return web.json_response({"ok":False,"reason":"no sub"}, status=400)
    res = {
        "daily":   _get_usage_slice(sub, "daily", 30),
        "weekly":  _get_usage_slice(sub, "weekly", 20),
        "monthly": _get_usage_slice(sub, "monthly", 12),
        "current": _current_usage_of(sub)
    }
    return web.json_response({"ok":True, **res})

# ===== 한도 API =====
@require_admin
async def api_limits_get(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    limits = (STATE.get("per_tunnel_limits") or {}).get(sub, {})
    return web.json_response({"ok":True,"sub":sub,"limits":limits})

@require_admin
async def api_limits_set(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    body = await request.json()
    def _to_bytes(v):
        if isinstance(v,(int,float)): return int(v)
        return 0
    daily = body.get("daily") or 0
    weekly= body.get("weekly") or 0
    monthly=body.get("monthly") or 0
    def conv_unit(x, mul):
        try: return int(float(x)*mul)
        except: return 0
    daily  = _to_bytes(daily)  or conv_unit(body.get("daily_mb"), 1048576)    or conv_unit(body.get("daily_gb"), 1073741824)
    weekly = _to_bytes(weekly) or conv_unit(body.get("weekly_mb"),1048576)    or conv_unit(body.get("weekly_gb"),1073741824)
    monthly= _to_bytes(monthly)or conv_unit(body.get("monthly_mb"),1048576)   or conv_unit(body.get("monthly_gb"),1073741824)
    STATE.setdefault("per_tunnel_limits", {})[sub] = {"daily":max(0,daily),"weekly":max(0,weekly),"monthly":max(0,monthly)}
    save_state(STATE)
    ring_log(f"ADMIN set limits for {sub}: {STATE['per_tunnel_limits'][sub]}")
    return web.json_response({"ok":True,"sub":sub,"limits":STATE["per_tunnel_limits"][sub]})

# ===== 접속 IP / 세션 조회 =====
def _history_day_keys(sub: str, days: int) -> List[str]:
    hist_map = IP_HISTORY.get(sub, {})
    keys = sorted(hist_map.keys())
    if days and keys:
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days - 1)).strftime("%Y-%m-%d")
        keys = [key for key in keys if key >= cutoff]
    return keys


def _paginate_rows(items: List[Any], page: int, page_size: int) -> Tuple[List[Any], int, int, int]:
    total = len(items)
    page_size = max(1, min(100, int(page_size or 20)))
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(pages, int(page or 1)))
    start = (page - 1) * page_size
    return items[start:start + page_size], total, pages, page


@require_admin
async def api_clients(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    days = max(1, min(365, int(request.query.get("days","30"))))
    current_ips = _current_ips_for(sub)
    hist_map = IP_HISTORY.get(sub, {})
    history_dates = [
        {"date": day, "count": len(hist_map.get(day, []) or [])}
        for day in _history_day_keys(sub, days)
    ]
    return web.json_response({
        "ok":True,
        "sub":sub,
        "current_ips": current_ips,
        "history_dates": history_dates,
        "blocked_ips": sorted(((STATE.get("per_tunnel_ip_deny") or {}).get(sub, []) or [])),
    })

@require_admin
async def api_client_history(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    date = (request.query.get("date") or "").strip()
    search = (request.query.get("search") or "").strip().lower()
    days = max(1, min(365, int(request.query.get("days", "30"))))
    page = int(request.query.get("page", "1"))
    page_size = int(request.query.get("page_size", "12"))
    hist_map = IP_HISTORY.get(sub, {})
    time_map = IP_TIMES.get(sub, {})

    if date:
        rows = []
        for ip in sorted(hist_map.get(date, []) or []):
            if search and search not in ip.lower():
                continue
            times = (time_map.get(date, {}).get(ip, []) or [])
            rows.append({
                "date": date,
                "ip": ip,
                "times": times,
                "count": len(times),
                "last_seen": times[-1] if times else "",
            })
    else:
        rows = []
        for day in reversed(_history_day_keys(sub, days)):
            for ip in sorted(hist_map.get(day, []) or []):
                if search and search not in ip.lower():
                    continue
                times = (time_map.get(day, {}).get(ip, []) or [])
                rows.append({
                    "date": day,
                    "ip": ip,
                    "times": times,
                    "count": len(times),
                    "last_seen": times[-1] if times else "",
                })

    page_items, total, pages, page = _paginate_rows(rows, page, page_size)
    return web.json_response({
        "ok": True,
        "sub": sub,
        "date": date or None,
        "search": search,
        "items": page_items,
        "total": total,
        "pages": pages,
        "page": page,
        "page_size": page_size,
    })

@require_admin
async def api_ip_sessions(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    ip = (request.query.get("ip") or "").strip()
    if not ip:
        return web.json_response({"ok":False,"reason":"no ip"}, status=400)
    days = max(1, min(365, int(request.query.get("days","30"))))
    ses = SESSIONS.get(sub, {})
    keys = sorted(ses.keys())
    if days and keys:
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days - 1)).strftime("%Y-%m-%d")
        keys = [key for key in keys if key >= cutoff]
    out=[]
    for day in keys:
        items = ses.get(day, {}).get(ip, [])
        if not items: continue
        out.append({"date": day, "items": items})
    return web.json_response({"ok":True, "sub":sub, "ip":ip, "sessions": out})

@require_admin
async def api_client_block_ip(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return web.json_response({"ok":False,"reason":"no_ip"}, status=400)
    deny_map = STATE.setdefault("per_tunnel_ip_deny", {})
    rules = list(deny_map.get(sub, []) or [])
    if ip not in rules:
        rules.append(ip)
    deny_map[sub] = sorted(set(rules))
    save_state(STATE)
    closed = await disconnect_ip(sub, ip)
    ring_log(f"ADMIN blocked IP {ip} on {sub} (closed={closed})")
    broadcast_refresh()
    return web.json_response({"ok":True, "sub":sub, "ip":ip, "closed":closed, "blocked_ips":deny_map[sub]})

@require_admin
async def api_client_unblock_ip(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return web.json_response({"ok":False,"reason":"no_ip"}, status=400)
    deny_map = STATE.setdefault("per_tunnel_ip_deny", {})
    rules = [rule for rule in (deny_map.get(sub, []) or []) if rule != ip]
    deny_map[sub] = rules
    save_state(STATE)
    ring_log(f"ADMIN unblocked IP {ip} on {sub}")
    broadcast_refresh()
    return web.json_response({"ok":True, "sub":sub, "ip":ip, "blocked_ips":rules})

@require_admin
async def api_add_mapping(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    info = TUNNELS.get(sub)
    if not info:
        return web.json_response({"ok":False, "reason":"tunnel_offline"}, status=409)

    body = await request.json()
    proto = (body.get("proto") or "").strip().lower()
    name = (body.get("name") or "").strip()
    host = (body.get("host") or "").strip()
    local_port = int(body.get("port") or 0)
    remote_port = int(body.get("remote_port") or 0)

    if proto not in ("tcp", "udp"):
        return web.json_response({"ok":False, "reason":"bad_proto"}, status=400)
    if not name or not name.isidentifier():
        return web.json_response({"ok":False, "reason":"bad_name"}, status=400)
    if not host or local_port <= 0 or local_port > 65535:
        return web.json_response({"ok":False, "reason":"bad_target"}, status=400)
    if remote_port < 0 or remote_port > 65535:
        return web.json_response({"ok":False, "reason":"bad_remote_port"}, status=400)

    runtime_bucket = info.get(proto, {})
    if name in runtime_bucket:
        return web.json_response({"ok":False, "reason":"duplicate_name"}, status=409)
    if name in managed_mapping_bucket(sub).get(proto, {}):
        return web.json_response({"ok":False, "reason":"duplicate_name"}, status=409)

    attach = attach_tcp_mapping if proto == "tcp" else attach_udp_mapping
    assigned, reason = await attach(sub, info["ws"], name, requested_port=remote_port, managed=True)
    if not assigned:
        return web.json_response({"ok":False, "reason":reason or "attach_failed"}, status=409)

    ok, control_reason = await send_control_and_wait(
        sub,
        "add_mapping",
        payload={
            "proto": proto,
            "mapping": {
                "name": name,
                "host": host,
                "port": local_port,
                "remote_port": assigned["remote_port"],
            },
        },
        timeout=8.0,
    )
    if not ok:
        await remove_runtime_mapping(sub, proto, name)
        return web.json_response({"ok":False, "reason":control_reason or "client_rejected"}, status=409)

    unsuppress_mapping(sub, proto, name)
    managed_mapping_bucket(sub)[proto][name] = {"host": host, "port": local_port, "remote_port": assigned["remote_port"]}
    save_state(STATE)
    ring_log(f"ADMIN added {proto.upper()} mapping {sub}/{name} -> {host}:{local_port} (remote {assigned['remote_port']})")
    broadcast_refresh()
    return web.json_response({"ok":True, "sub":sub, "proto":proto, "mapping":assigned})

@require_admin
async def api_delete_mapping(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    proto = (request.match_info["proto"] or "").strip().lower()
    name = (request.match_info["name"] or "").strip()
    if proto not in ("tcp", "udp"):
        return web.json_response({"ok":False, "reason":"bad_proto"}, status=400)
    if not name:
        return web.json_response({"ok":False, "reason":"bad_name"}, status=400)

    managed = managed_mapping_bucket(sub).get(proto, {})
    source = "managed" if name in managed else "client"
    if source == "managed":
        managed.pop(name, None)
    else:
        suppress_mapping(sub, proto, name)
    save_state(STATE)

    info = TUNNELS.get(sub)
    client_notified = False
    if info:
        if name in info.get(proto, {}):
            await remove_runtime_mapping(sub, proto, name)
        notified, _ = await send_control_and_wait(
            sub,
            "remove_mapping",
            payload={"proto": proto, "name": name, "source": source},
            timeout=5.0,
        )
        client_notified = notified

    ring_log(f"ADMIN removed {proto.upper()} mapping {sub}/{name} source={source} notified={client_notified}")
    broadcast_refresh()
    return web.json_response({"ok":True, "sub":sub, "proto":proto, "name":name, "source":source, "client_notified":client_notified})

# ===== 로그 파일 목록/조회 =====
@require_admin
async def api_logs_list(request: web.Request) -> web.Response:
    files = list_log_files(force=request.query.get("refresh") == "1")
    return web.json_response({"ok":True, "files": files})

@require_admin
async def api_logs_get(request: web.Request) -> web.Response:
    try:
        name = request.query.get("name","")
        if not name:
            return web.Response(status=400, text="missing name")
        safe = os.path.basename(name)
        if safe != name:
            return web.Response(status=400, text="bad name")
        path = os.path.join(LOG_DIR, safe)
        if not os.path.exists(path):
            return web.Response(status=404, text="not found")
        if not os.path.isfile(path):
            return web.Response(status=400, text="not a file")
        mode = (request.query.get("mode") or "tail").strip().lower()
        as_json = request.query.get("fmt") == "json"
        meta = next((item for item in list_log_files() if item["name"] == safe), None)
        if mode == "full":
            with open(path,"r",encoding="utf-8",errors="replace") as f:
                data = f.read()
            truncated = False
        else:
            data, truncated = read_log_tail(
                path,
                max_lines=int(request.query.get("lines", "800")),
                max_bytes=int(request.query.get("max_bytes", str(256 * 1024))),
            )
        if as_json:
            return web.json_response({
                "ok": True,
                "name": safe,
                "mode": mode,
                "truncated": truncated,
                "meta": meta or {},
                "text": data,
            })
        return web.Response(status=200, text=data, content_type="text/plain", charset="utf-8")
    except PermissionError:
        return web.Response(status=403, text="forbidden")
    except Exception as e:
        logger.exception("api_logs_get failed: %s", e)
        return web.Response(status=500, text="internal error")

# ===== 대역폭/저장 루프 =====
async def bw_loop():
    global _bw_counters, _bw_total
    while True:
        await asyncio.sleep(1.0)
        items = _bw_counters
        total = _bw_total
        _bw_counters = {}
        _bw_total = {"tx":0,"rx":0}

        if items:
            for sub, v in items.items():
                _add_usage(sub, tx=v.get("tx",0), rx=v.get("rx",0))
        _save_usage_if_needed()
        _save_ip_hist_if_needed()
        _save_ip_times_if_needed()
        _save_sessions_if_needed()

        payload = {"kind":"bandwidth","ts": time.time(), "items": items, "total": total}
        broadcast(payload)

# = 앱 구성 =
async def make_app() -> web.Application:
    app = web.Application(client_max_size=64*1024*1024, middlewares=[admin_ip_mw])
    app.add_routes([
        web.get("/_ws", ws_handler),

        # 로그인/로그아웃 & 대시보드
        web.get("/login", login),
        web.post("/api/login", api_login),
        web.get("/dashboard", dashboard_page),
        web.get("/logout", logout),
        web.get("/admin_ws", admin_ws),

        # 관리/조회 API
        web.get ("/api/tunnels", api_tunnels),
        web.post("/api/tunnels/{sub}/disconnect", api_disconnect),
        web.post("/api/tunnels/{sub}/reconnect", api_reconnect),
        web.post("/api/tunnels/{sub}/mappings", api_add_mapping),
        web.delete("/api/tunnels/{sub}/mappings/{proto}/{name}", api_delete_mapping),
        web.post("/api/admin/ip-allow", api_set_ip_allow),
        web.post("/api/admin/tokens", api_set_tokens),
        web.get ("/api/admin/tokens/meta", api_token_meta),
        web.post("/api/admin/token/revoke", api_token_revoke),
        web.post("/api/admin/logs/clear", api_logs_clear),
        web.post("/api/admin/schedule", api_schedule_set),
        web.get ("/api/admin/schedule/{sub}",  api_tunnel_schedule_get),
        web.post("/api/admin/schedule/{sub}",  api_tunnel_schedule_set),
        web.post("/api/admin/tunnel-ip-deny", api_set_tunnel_deny),
        web.post("/api/admin/bot-blocking", api_set_bot_blocking),

        # 집계/제한
        web.get ("/api/stats/usage", api_usage),
        web.get ("/api/stats/usage/all", api_usage_all),
        web.get ("/api/admin/limits/{sub}", api_limits_get),
        web.post("/api/admin/limits/{sub}", api_limits_set),

        # 접속 IP / 세션
        web.get ("/api/admin/clients/{sub}", api_clients),
        web.get ("/api/admin/clients/{sub}/history", api_client_history),
        web.get ("/api/admin/clients/{sub}/sessions", api_ip_sessions),
        web.post("/api/admin/clients/{sub}/block-ip", api_client_block_ip),
        web.post("/api/admin/clients/{sub}/unblock-ip", api_client_unblock_ip),

        # 로그 파일 목록/조회
        web.get("/api/logs/list", api_logs_list),
        web.get("/api/logs/get", api_logs_get),

        # 공개 HTTP 프록시
        web.route("*","/{tail:.*}", public_http_handler),
    ])
    app["bw_task"] = asyncio.create_task(bw_loop())
    return app

def main():
    if any(arg in ("-v", "--version") for arg in sys.argv[1:]):
        print(f"{APP_NAME} {APP_VERSION}")
        return
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app = loop.run_until_complete(make_app())
    runner = web.AppRunner(app)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, host=os.getenv("BIND","0.0.0.0"), port=int(os.getenv("PORT","8080")))
    loop.run_until_complete(site.start())
    logger.info("Tunnel server started on %s:%s", os.getenv("BIND","0.0.0.0"), os.getenv("PORT","8080"))
    ring_log("SERVER STARTED")

    stop = asyncio.Event()
    def _stop(): stop.set()
    for s in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(s, _stop)
    loop.run_until_complete(stop.wait())
    logger.info("Shutting down...")
    ring_log("SERVER STOP")
    with contextlib.suppress(Exception):
        app["bw_task"].cancel()
    _save_usage_if_needed(force=True)
    _save_ip_hist_if_needed(force=True)
    _save_ip_times_if_needed(force=True)
    _save_sessions_if_needed(force=True)
    loop.run_until_complete(runner.cleanup())
    loop.close()

if __name__=="__main__":
    main()
