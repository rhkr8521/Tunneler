#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio, base64, json, logging, os, signal, socket, uuid, ipaddress, datetime, time, contextlib
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

# ===== 전역 상태 =====
TUNNELS: Dict[str, Dict[str, Any]] = {}   # subdomain -> {ws, tcp:{}, udp:{}}
PENDING: Dict[str, asyncio.Future] = {}   # HTTP 프록시 응답 대기
ADMIN_WSS: List[web.WebSocketResponse] = []  # 대시보드 실시간 구독자(관리자 WS)

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

def _start_session(sub: str, ip: str, when: Optional[datetime.datetime]=None):
    global _sessions_dirty
    if not when: when = datetime.datetime.now()
    day = when.strftime("%Y-%m-%d")
    rec = {"start": when.replace(microsecond=0).isoformat(), "end": None}
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

# 상태 파일
STATE_FILE = os.getenv("ADMIN_STATE_FILE", "/opt/tunneler/admin_state.json")
def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            "admin_ip_allow": [],
            "access_schedules": [],
            "per_tunnel_schedules": {},
            "token_meta": {},
            "tunnel_ip_deny": [],
            "per_tunnel_limits": {}
        }
    try:
        with open(STATE_FILE,"r",encoding="utf-8") as f:
            s=json.load(f)
            s.setdefault("admin_ip_allow",[])
            s.setdefault("access_schedules",[])
            s.setdefault("per_tunnel_schedules",{})
            s.setdefault("token_meta",{})
            s.setdefault("tunnel_ip_deny",[])
            s.setdefault("per_tunnel_limits",{})
            return s
    except Exception:
        return {"admin_ip_allow": [], "access_schedules": [], "per_tunnel_schedules": {}, "token_meta": {}, "tunnel_ip_deny": [], "per_tunnel_limits": {}}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE,"w",encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

STATE = load_state()

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
LOG_RING: List[str] = []
MAX_LOG_LINES = 500
def ring_log(line: str):
    LOG_RING.append(line)
    if len(LOG_RING) > MAX_LOG_LINES:
        del LOG_RING[:len(LOG_RING)-MAX_LOG_LINES]
    logger.info(line)

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: Optional[str]) -> bytes: return base64.b64decode((s or "").encode("ascii")) if s else b""

def extract_subdomain(host: str) -> Optional[str]:
    host = host.split(":")[0]; parts = host.split(".")
    return parts[0] if len(parts) >= 3 else None

def client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff: return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP")
    if xri: return xri.strip()
    return request.remote or "127.0.0.1"

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

# === 터널 접근 차단 IP ===
def tunnel_ip_blocked(ip: str) -> bool:
    deny = STATE.get("tunnel_ip_deny", [])
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

def require_admin(handler):
    async def wrapper(request: web.Request):
        ip = client_ip(request)
        if not ip_allowed(ip):
            return web.Response(status=403, text="Forbidden by IP allowlist")
        if parse_basic_auth(request):
            resp = await handler(request)
            if request.cookies.get("admin_block"):
                try: resp.del_cookie("admin_block", path="/")
                except Exception: pass
            return resp
        resp = web.Response(status=401, text="Unauthorized")
        resp.headers["WWW-Authenticate"] = 'Basic realm="tunneler-admin"'
        return resp
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

# ===== WS 핸들러 (클라이언트) =====
async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=20.0)
    await ws.prepare(request)
    peer = client_ip(request)
    logger.info("WS connected from %s", peer); ring_log(f"WS connected: {peer}")

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
                    tcp_cfgs = data.get("tcp_configs",[]) or []
                    udp_cfgs = data.get("udp_configs",[]) or []

                    if not candidate or not candidate.isalnum():
                        await ws.send_json({"type":"register_result","ok":False,"reason":"bad_subdomain"}); continue

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
                    TUNNELS[subdomain] = {"ws":ws,"tcp":{},"udp":{}}
                    ring_log(f"REGISTER {subdomain} by {peer}")
                    broadcast({"kind":"register","subdomain":subdomain})

                    # TCP 리스너
                    tcp_assigned=[]
                    for cfg in tcp_cfgs:
                        name=cfg.get("name"); req=int(cfg.get("remote_port",0))
                        if not name or not name.isidentifier(): continue
                        port = req if req else (await alloc_port(TCP_START,TCP_END,INUSE_TCP,socket.SOCK_STREAM))
                        if not port or port in INUSE_TCP: continue

                        async def _tcp_handler(reader, writer, _name=name, _sub=subdomain):
                            pinfo = writer.get_extra_info("peername")
                            rip = (pinfo[0] if pinfo else "") or "0.0.0.0"
                            if tunnel_ip_blocked(rip) or not access_allowed_for(_sub) or not allowed_by_limit(_sub):
                                with contextlib.suppress(Exception):
                                    writer.close(); await writer.wait_closed()
                                return
                            sid=str(uuid.uuid4())
                            sess_key = _start_session(_sub, rip)
                            TUNNELS[_sub]["tcp"][_name]["streams"][sid]={"reader":reader,"writer":writer,"rip":rip,"sess_key":sess_key}
                            _ip_inc(_sub, rip); _record_ip_seen(_sub, rip)

                            sock=writer.get_extra_info("socket")
                            if sock is not None:
                                import socket as pysock
                                with contextlib.suppress(Exception):
                                    sock.setsockopt(pysock.IPPROTO_TCP, pysock.TCP_NODELAY, 1)
                            await ws.send_json({"type":"tcp_open","name":_name,"stream_id":sid})
                            ring_log(f"TCP OPEN {_sub}/{_name}/{sid} from {rip}")

                            async def pump_up():
                                try:
                                    while True:
                                        if not access_allowed_for(_sub) or not allowed_by_limit(_sub): break
                                        chunk=await reader.read(65536)
                                        if not chunk: break
                                        _bw_acc(_sub,"rx",len(chunk)); _add_usage(_sub, tx=0, rx=len(chunk))
                                        await ws.send_json({"type":"tcp_data","stream_id":sid,"b64":b64e(chunk)})
                                except Exception:
                                    pass
                                finally:
                                    await ws.send_json({"type":"tcp_close","stream_id":sid,"who":"server"})
                            asyncio.create_task(pump_up())

                        server_obj = await asyncio.start_server(_tcp_handler,"0.0.0.0",port)
                        INUSE_TCP.add(port)
                        TUNNELS[subdomain]["tcp"][name]={"port":port,"server":server_obj,"streams":{}}
                        tcp_assigned.append({"name":name,"remote_port":port})

                    # UDP 리스너
                    udp_assigned=[]
                    for cfg in udp_cfgs:
                        name=cfg.get("name"); req=int(cfg.get("remote_port",0))
                        if not name or not name.isidentifier(): continue
                        port = req if req else (await alloc_port(UDP_START,UDP_END,INUSE_UDP,socket.SOCK_DGRAM))
                        if not port or port in INUSE_UDP: continue

                        loop=asyncio.get_running_loop()
                        flows={}; FLOW_IDLE=30.0
                        class UdpProto(asyncio.DatagramProtocol):
                            def connection_made(self, transport): self.transport=transport
                            def datagram_received(self, data, addr):
                                rip = addr[0] if addr else "0.0.0.0"
                                if tunnel_ip_blocked(rip) or not access_allowed_for(subdomain) or not allowed_by_limit(subdomain): return
                                if addr not in flows:
                                    fid=str(uuid.uuid4())
                                    sess_key = _start_session(subdomain, rip)
                                    flows[addr]={"flow_id":fid,"last":loop.time(),"rip":rip,"sess_key":sess_key}
                                    _ip_inc(subdomain, rip); _record_ip_seen(subdomain, rip)
                                    asyncio.create_task(ws.send_json({"type":"udp_open","name":name,"flow_id":fid}))
                                flows[addr]["last"]=loop.time()
                                fid=flows[addr]["flow_id"]
                                _bw_acc(subdomain or "", "rx", len(data)); _add_usage(subdomain or "", tx=0, rx=len(data))
                                asyncio.create_task(ws.send_json({"type":"udp_data","flow_id":fid,"b64":b64e(data)}))
                        transport, protocol = await loop.create_datagram_endpoint(lambda: UdpProto(), local_addr=("0.0.0.0",port))
                        INUSE_UDP.add(port)
                        async def gc():
                            while True:
                                await asyncio.sleep(5)
                                now=loop.time()
                                for k,v in list(flows.items()):
                                    if now - v["last"] > FLOW_IDLE:
                                        fid=v["flow_id"]; rip=v.get("rip",""); sess_key=v.get("sess_key")
                                        flows.pop(k,None)
                                        if rip: _ip_dec(subdomain, rip)
                                        if sess_key: _end_session(sess_key)
                                        await ws.send_json({"type":"udp_close","flow_id":fid,"who":"server"})
                        asyncio.create_task(gc())
                        TUNNELS[subdomain]["udp"][name]={"port":port,"transport":transport,"flows":flows}
                        udp_assigned.append({"name":name,"remote_port":port})

                    await ws.send_json({"type":"register_result","ok":True,"tcp_assigned":tcp_assigned,"udp_assigned":udp_assigned})
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
                                rip = st.get("rip","");
                                if rip: _ip_dec(subdomain, rip)
                                sess_key = st.get("sess_key");
                                if sess_key: _end_session(sess_key)
                                with contextlib.suppress(Exception):
                                    st["writer"].close()
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
                                    rip = meta.get("rip","");
                                    if rip: _ip_dec(subdomain, rip)
                                    sess_key = meta.get("sess_key");
                                    if sess_key: _end_session(sess_key)
                                    ud["flows"].pop(addr,None); break

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
                    with contextlib.suppress(Exception): t["server"].close()
                    INUSE_TCP.discard(t["port"])
                    for st in list(t.get("streams",{}).values()):
                        rip = st.get("rip","");
                        if rip: _ip_dec(sub, rip)
                        sess_key = st.get("sess_key")
                        if sess_key: _end_session(sess_key)
                for u in info.get("udp",{}).values():
                    with contextlib.suppress(Exception): u["transport"].close()
                    INUSE_UDP.discard(u["port"])
                    for meta in list(u.get("flows",{}).values()):
                        rip = meta.get("rip","");
                        if rip: _ip_dec(sub, rip)
                        sess_key = meta.get("sess_key")
                        if sess_key: _end_session(sess_key)
                TUNNELS.pop(sub, None)
                ring_log(f"UNREGISTER {sub}")
                broadcast({"kind":"unregister","subdomain":sub})
                break
    return ws

# 공개 HTTP 프록시 + /_health
async def public_http_handler(request: web.Request) -> web.StreamResponse:
    if request.path == "/_health":
        return web.json_response({
            "ok": True,
            "tunnels": {
                k:{
                    "tcp":{n:v["port"] for n,v in TUNNELS[k].get("tcp",{}).items()},
                    "udp":{n:v["port"] for n,v in TUNNELS[k].get("udp",{}).items()},
                } for k in TUNNELS.keys()
            }
        })

    ip = client_ip(request)
    host = request.headers.get("Host","")
    sub = extract_subdomain(host) or request.rel_url.query.get("x-subdomain")
    if not sub or sub not in TUNNELS:
        return web.Response(status=404, text="No tunnel for this host")
    if tunnel_ip_blocked(ip) or not access_allowed_for(sub):
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
DASH_HTML = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Tunneler Admin</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
#toast { position: fixed; top: 16px; right: 16px; z-index: 9999; display: flex; flex-direction: column; gap: 8px; }
.toast { background: #111827; color: #e5e7eb; padding: 10px 14px; border-radius: 10px; box-shadow: 0 10px 20px rgba(0,0,0,.15); font-size: 14px; }
#modalOverlay { position: fixed; inset:0; background: rgba(15,23,42,.6); display: none; align-items:center; justify-content:center; z-index: 9998;}
.modal-card { width: 92%; max-width: 980px; background: white; border-radius: 16px; box-shadow: 0 20px 40px rgba(0,0,0,.25); }
.modal-head { padding: 14px 18px; font-weight: 700; border-bottom: 1px solid #e5e7eb;}
.modal-body { padding: 16px 18px; max-height: 72vh; overflow:auto;}
.modal-foot { padding: 12px 18px; display:flex; gap:8px; border-top: 1px solid #e5e7eb; }
.modal-foot .spacer { flex: 1; }
.grid-auto { display:grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
.badge { display:inline-block; background:#eef2ff; color:#1e293b; padding:4px 9px; border-radius:9999px; font-size:12px; border:1px solid #c7d2fe; cursor:pointer; user-select:none; }
.badge:hover { background:#e0e7ff; }
</style>
</head>
<body class="bg-slate-50 text-slate-800">
<div id="toast"></div>
<div id="modalOverlay"><div class="modal-card">
  <div class="modal-head" id="modalTitle">Modal</div>
  <div class="modal-body" id="modalBody"></div>
  <div class="modal-foot">
    <div class="spacer"></div>
    <button id="modalCancel" class="px-3 py-1.5 rounded bg-slate-200 hover:bg-slate-300">취소</button>
    <button id="modalOk" class="px-3 py-1.5 rounded bg-indigo-600 text-white hover:bg-indigo-700">확인</button>
  </div>
</div></div>

<div class="max-w-7xl mx-auto p-4">
  <header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between py-3">
    <h1 class="text-2xl font-bold">Tunneler 대시보드</h1>
    <div class="flex items-center gap-2 flex-wrap">
      <button id="openAgg" class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-sm">집계/제한</button>
      <a href="/logout" class="px-3 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 text-sm">로그아웃</a>
      <div class="text-sm text-slate-500" id="rangeInfo"></div>
    </div>
  </header>

  <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 my-3" id="stats">
    <div class="bg-white rounded-xl shadow p-4">
      <div class="text-sm text-slate-500">활성 서브도메인</div>
      <div class="text-2xl font-bold mt-1" id="statSubs">-</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4"><div class="text-sm text-slate-500">할당 TCP 포트 수</div><div class="text-2xl font-bold mt-1" id="statTCP">-</div></div>
    <div class="bg-white rounded-xl shadow p-4"><div class="text-sm text-slate-500">할당 UDP 포트 수</div><div class="text-2xl font-bold mt-1" id="statUDP">-</div></div>
    <div class="bg-white rounded-xl shadow p-4"><div class="text-sm text-slate-500">총 Up</div><div class="text-2xl font-bold mt-1" id="statUp">0 B/s</div></div>
    <div class="bg-white rounded-xl shadow p-4"><div class="text-sm text-slate-500">총 Down</div><div class="text-2xl font-bold mt-1" id="statDown">0 B/s</div></div>
  </section>

  <section class="mt-5">
    <div class="flex items-center justify-between mb-2">
      <h2 class="text-lg font-semibold">활성 터널</h2>
      <div class="flex gap-2">
        <button id="prevLogsBtn" class="px-3 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300">이전 로그 보기</button>
        <button id="refreshBtn" class="px-3 py-1.5 rounded-lg bg-indigo-600 text-white hover:bg-indigo-700">수동 새로고침</button>
      </div>
    </div>
    <div id="list" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3"></div>
  </section>

  <section class="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">대시보드 IP 제한</h3>
      <p class="text-sm text-slate-500 mb-2">허용할 IP 또는 CIDR(쉼표 구분). 비워두면 제한 없음.</p>
      <input id="ipAllow" class="w-full border rounded-lg p-2 mb-2" placeholder="예: 1.2.3.4, 10.0.0.0/24"/>
      <div class="flex justify-end">
        <button id="saveIp" class="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-700 text-white">저장</button>
      </div>
    </div>

    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">접속 허용 시간대(전역)</h3>
      <p class="text-sm text-slate-500 mb-2">예) mon-fri 09:00~18:00, sat-sun 10:00~16:00</p>
      <div class="space-y-2" id="schList"></div>
      <div class="flex justify-end mt-2">
        <button id="saveSch" class="px-3 py-1.5 rounded bg-sky-700 hover:bg-sky-800 text-white">저장</button>
      </div>
    </div>
  </section>

  <section class="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">클라이언트 토큰(화이트리스트)</h3>
      <p class="text-sm text-slate-500 mb-2">쉼표로 구분. 비워두면 인증 없이 허용(개발용).</p>
      <input id="tokens" class="w-full border rounded-lg p-2 mb-2" placeholder="예: AAA, BBB, TEAM-ALPHA"/>
      <div class="flex justify-end">
        <button id="saveTok" class="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-700 text-white">저장</button>
      </div>
      <h4 class="font-semibold mt-4 mb-1">토큰 마지막 사용 / 빠른 무효화</h4>
      <div id="tokMeta" class="text-sm"></div>
    </div>

    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">터널 접근 차단 IP/CIDR</h3>
      <p class="text-sm text-slate-500 mb-2">외부 사용자가 공개 포트로 접근하는 것을 차단. 쉼표 구분.</p>
      <input id="denyIp" class="w-full border rounded-lg p-2 mb-2" placeholder="예: 203.0.113.5, 10.0.0.0/8">
      <div class="flex justify-end">
        <button id="saveDeny" class="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-700 text-white">저장</button>
      </div>
    </div>
  </section>

  <section class="mt-8">
    <h3 class="font-semibold mb-2">실시간 대역폭(초당)</h3>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mb-2">
      <div class="bg-white rounded-xl shadow p-4"><div class="text-sm text-slate-500">총 Up</div><div class="text-2xl font-bold mt-1" id="totalUp">0 B/s</div></div>
      <div class="bg-white rounded-xl shadow p-4"><div class="text-sm text-slate-500">총 Down</div><div class="text-2xl font-bold mt-1" id="totalDown">0 B/s</div></div>
      <div class="bg-white rounded-xl shadow p-4"><div class="text-sm text-slate-500">활성 터널 수(초당 갱신)</div><div class="text-2xl font-bold mt-1" id="bwSubs">0</div></div>
    </div>
    <div class="overflow-x-auto">
      <table class="min-w-full text-sm border rounded" id="bwTable">
        <thead class="bg-slate-100">
          <tr><th class="text-left p-2">Subdomain</th><th class="text-left p-2">Up</th><th class="text-left p-2">Down</th></tr>
        </thead>
        <tbody id="bwBody"></tbody>
      </table>
    </div>
  </section>

  <section class="mt-8">
    <div class="flex items-center justify-between mb-2">
      <h3 class="font-semibold">서버 로그</h3>
      <div class="flex gap-2 flex-wrap">
        <select id="logSel" class="border rounded p-1 text-sm"></select>
        <button id="loadSel" class="px-3 py-1.5 rounded bg-slate-200 hover:bg-slate-300 text-sm">선택 로그 보기</button>
        <button id="prevLogsBtn2" class="px-3 py-1.5 rounded bg-slate-200 hover:bg-slate-300 text-sm">이전 로그 보기</button>
        <button id="clearLog" class="px-3 py-1.5 rounded bg-slate-200 hover:bg-slate-300 text-sm">지우기</button>
      </div>
    </div>
    <pre id="logs" class="bg-black text-green-200 text-xs p-3 rounded-xl h-64 overflow-auto"></pre>
  </section>

  <footer class="w-full text-center text-sm text-gray-500 py-6 border-t mt-10">
    <div>rhkr8521 Tunneler</div>
    <div>© Copyright rhkr8521. All rights reserved.</div>
  </footer>
</div>

<script>
let ws;

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
    const close = () => { ov.style.display='none'; ok.onclick=null; no.onclick=null; }
    ok.onclick = ()=>{ resolve(true); close(); }
    no.onclick = ()=>{ resolve(false); close(); }
    ov.style.display='flex';
  });
}

/* ===== API 헬퍼 ===== */
async function api(path, opts={}){ 
  const r=await fetch(path, opts); 
  if(r.status===401){ location.href='/login'; return; } 
  const ct = r.headers.get('content-type')||'';
  if(ct.includes('application/json')) return r.json();
  return r.text();
}

/* ===== 포맷 ===== */
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

/* ===== 로그 목록 ===== */
async function loadLogList(){
  const d = await api('/api/logs/list');
  const sel = document.getElementById('logSel'); sel.innerHTML='';
  (d.files||[]).forEach(f=>{
    const o=document.createElement('option'); o.value=f; o.textContent=f; sel.appendChild(o);
  });
}
async function loadLogListAndOpenFirst(){
  const d = await api('/api/logs/list');
  const sel = document.getElementById('logSel'); sel.innerHTML='';
  (d.files||[]).forEach(f=>{
    const o=document.createElement('option'); o.value=f; o.textContent=f; sel.appendChild(o);
  });
  if ((d.files||[]).length > 0) {
    sel.selectedIndex = 0;
    const r = await fetch('/api/logs/get?name='+encodeURIComponent(sel.value));
    const text = await r.text();
    const pre=document.getElementById('logs'); pre.textContent = text; pre.scrollTop = pre.scrollHeight;
    showToast('로그 로드 완료','ok');
  } else {
    showToast('표시할 로그가 없습니다.','warn');
  }
}

/* ===== 스냅샷 ===== */
let lastSnapshot = null;
async function loadSnapshot(){
  const d = await api('/api/tunnels'); if(!d) return;
  lastSnapshot = d;
  const t=d.tunnels||{}; const keys=Object.keys(t).sort();
  document.getElementById('rangeInfo').textContent = d.range || '';
  document.getElementById('statSubs').textContent = keys.length;
  document.getElementById('statTCP').textContent = keys.reduce((a,k)=>a+Object.keys(t[k].tcp||{}).length,0);
  document.getElementById('statUDP').textContent = keys.reduce((a,k)=>a+Object.keys(t[k].udp||{}).length,0);
  document.getElementById('bwSubs').textContent = keys.length;

  const list=document.getElementById('list'); list.innerHTML="";
  keys.forEach(sub=>{
    const o=t[sub]||{}, tcp=o.tcp||{}, udp=o.udp||{};
    const tcpList=Object.entries(tcp).map(([n,p])=>`<span class="px-2 py-1 rounded bg-slate-100 text-xs">${n}=<b>${p}</b></span>`).join(" ");
    const udpList=Object.entries(udp).map(([n,p])=>`<span class="px-2 py-1 rounded bg-slate-100 text-xs">${n}=<b>${p}</b></span>`).join(" ");
    const card=document.createElement('div');
    card.className='bg-white rounded-2xl shadow p-4 flex flex-col gap-3';

    const h=document.createElement('div'); h.className='flex items-center justify-between';
    const title=document.createElement('div'); title.className='text-lg font-semibold'; title.textContent=sub;
    h.appendChild(title);

    const btnWrap=document.createElement('div'); btnWrap.className='flex gap-2 flex-wrap';

    const limitBtn=document.createElement('button');
    limitBtn.className='px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-700 text-white text-sm';
    limitBtn.textContent='제한';
    limitBtn.onclick = ()=> openLimitModal(sub);
    btnWrap.appendChild(limitBtn);

    const scheduleBtn=document.createElement('button');
    scheduleBtn.className='px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-700 text-white text-sm';
    scheduleBtn.textContent='시간대';
    scheduleBtn.onclick = async ()=>{
      const cur = await api(`/api/admin/schedule/${sub}`);
      const items = await openScheduleModal(sub, cur.items||[]);
      if(items===null) return;
      await fetch(`/api/admin/schedule/${sub}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(items)});
      await loadSnapshot();
      await renderGlobalScheduleList(); // 보조 갱신
      showToast('저장되었습니다.','ok');
    };
    btnWrap.appendChild(scheduleBtn);

    const clientsBtn=document.createElement('button');
    clientsBtn.className='px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-sm';
    clientsBtn.textContent='접속IP';
    clientsBtn.onclick=()=> openClientsModal(sub);
    btnWrap.appendChild(clientsBtn);

    const disBtn=document.createElement('button');
    disBtn.className='px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-700 text-white text-sm';
    disBtn.textContent='Disconnect';
    disBtn.onclick=async()=>{
      const ok = await confirmAsync(`${sub} 터널을 종료할까요?`);
      if(!ok) return;
      await fetch(`/api/tunnels/${sub}/disconnect`,{method:'POST'});
      showToast('터널 종료 요청을 전송했습니다.','ok');
    };
    btnWrap.appendChild(disBtn);

    h.appendChild(btnWrap);
    card.appendChild(h);

    const sec1=document.createElement('div'); sec1.className='text-sm';
    sec1.innerHTML='<span class="font-medium">TCP</span><div class="mt-1 flex flex-wrap gap-1">'+(tcpList||'<span class="text-slate-400">없음</span>')+'</div>';
    const sec2=document.createElement('div'); sec2.className='text-sm';
    sec2.innerHTML='<span class="font-medium">UDP</span><div class="mt-1 flex flex-wrap gap-1">'+(udpList||'<span class="text-slate-400">없음</span>')+'</div>';

    card.appendChild(sec1); card.appendChild(sec2);
    list.appendChild(card);
  });

  document.getElementById('ipAllow').value = (d.admin_ip_allow||[]).join(', ');
  document.getElementById('tokens').value = (d.tokens||[]).join(', ');
  document.getElementById('denyIp').value = (d.tunnel_ip_deny||[]).join(', ');

  await renderGlobalScheduleList(d); // 전역 시간대 리스트 반영
}

async function renderGlobalScheduleList(snapshot=null){
  const d = snapshot || await api('/api/tunnels');
  const gl = (d && d.access_schedules) || [];
  const box = document.getElementById('schList');
  box.innerHTML = gl.length ? 
    gl.map(x=>`<div class="px-2 py-1 rounded bg-slate-100 inline-block mr-2 mb-2 text-sm">${(x.days||'all')} ${(x.start||'00:00')}~${(x.end||'23:59')}</div>`).join('') :
    '<div class="text-slate-400 text-sm">설정 없음 (24시간 허용)</div>';
}

/* ===== 토큰 메타 ===== */
async function loadTokenMeta(){
  const tm = await api('/api/admin/tokens/meta');
  const box = document.getElementById('tokMeta'); box.innerHTML='';
  const tbl = document.createElement('table'); tbl.className='w-full text-sm';
  tbl.innerHTML = `<thead>
      <tr class="text-left text-slate-500">
        <th class="py-1 pr-2">Token</th><th class="py-1 pr-2">Last IP</th><th class="py-1 pr-2">Last At(UTC)</th><th></th>
      </tr></thead><tbody></tbody>`;
  const tb = tbl.querySelector('tbody');
  (tm.items||[]).forEach(r=>{
    const tr = document.createElement('tr'); tr.className='border-top';
    tr.innerHTML = `
      <td class="py-1 pr-2">${r.token}</td>
      <td class="py-1 pr-2">${r.last_ip||''}</td>
      <td class="py-1 pr-2">${r.last_at||''}</td>
      <td class="py-1 pr-2">
        <button class="px-2 py-1 rounded bg-rose-600 hover:bg-rose-700 text-white" data-token="${r.token}">무효화</button>
      </td>`;
    tr.querySelector('button').onclick=async(e)=>{
      const ok = await confirmAsync('해당 토큰을 즉시 무효화할까요?');
      if(!ok) return;
      const tok = e.target.getAttribute('data-token');
      await fetch('/api/admin/token/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})});
      await loadSnapshot();
      await loadTokenMeta();
      showToast('토큰을 무효화했습니다.','ok');
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
        const tbody=document.getElementById('bwBody');
        const items = msg.items||{};
        const tot = msg.total || {tx:0, rx:0};
        document.getElementById('totalUp').textContent = formatRate(tot.tx||0);
        document.getElementById('totalDown').textContent = formatRate(tot.rx||0);
        document.getElementById('statUp').textContent = formatRate(tot.tx||0);
        document.getElementById('statDown').textContent = formatRate(tot.rx||0);
        document.getElementById('bwSubs').textContent = Object.keys(items).length;

        tbody.innerHTML='';
        Object.keys(items).sort().forEach(sub=>{
          const v=items[sub]||{};
          const tr=document.createElement('tr');
          tr.innerHTML = `<td class="p-2">${sub}</td><td class="p-2">${formatRate(v.tx||0)}</td><td class="p-2">${formatRate(v.rx||0)}</td>`;
          tbody.appendChild(tr);
        });
      }else if(['register','unregister','assigned'].includes(msg.kind)){
        loadSnapshot();
      }else if(msg.kind==='snapshot_logs'){
        const pre=document.getElementById('logs'); pre.textContent = (msg.lines||[]).join("\\n");
        pre.scrollTop = pre.scrollHeight;
      }
    }catch(e){}
  };
  ws.onclose = ()=> setTimeout(connectWS, 2000);
}

/* ===== 집계/제한 모달 ===== */
let chartD=null, chartW=null, chartM=null;

async function openAggModal(){
  const subs = Object.keys((lastSnapshot&&lastSnapshot.tunnels)||{}).sort();
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
  document.getElementById('btnSetLimit').onclick = ()=> openLimitModal(document.getElementById('aggSub').value);
  document.getElementById('btnViewGraph').onclick = ()=> { document.getElementById('aggGraphs').classList.remove('hidden'); document.getElementById('aggTables').classList.add('hidden'); };
  document.getElementById('btnViewTable').onclick = ()=> { document.getElementById('aggGraphs').classList.add('hidden'); document.getElementById('aggTables').classList.remove('hidden'); };
  if(subs.length>0) renderAggCharts(subs[0]);
  await p;
}

function makeTableHtml(rows){
  const th = `<thead class="bg-slate-100"><tr><th class="text-left p-2">기간</th><th class="text-right p-2">TX (MB)</th><th class="text-right p-2">RX (MB)</th><th class="text-right p-2">TOTAL (MB)</th></tr></thead>`;
  const tb = rows.map(r=>`<tr><td class="p-2">${r.key}</td><td class="p-2 text-right">${(r.tx/1048576).toFixed(2)}</td><td class="p-2 text-right">${(r.rx/1048576).toFixed(2)}</td><td class="p-2 text-right">${(r.total/1048576).toFixed(2)}</td></tr>`).join('');
  return `<table class="min-w-full text-sm border rounded"><tbody>${th}${tb}</tbody></table>`;
}

async function renderAggCharts(sub){
  const daily = await api(`/api/stats/usage?sub=${encodeURIComponent(sub)}&period=daily&limit=30`);
  const weekly= await api(`/api/stats/usage?sub=${encodeURIComponent(sub)}&period=weekly&limit=20`);
  const monthly=await api(`/api/stats/usage?sub=${encodeURIComponent(sub)}&period=monthly&limit=12`);
  const mk = (arr)=>({
    labels: arr.map(x=>x.key),
    tx: arr.map(x=>x.tx/1048576),
    rx: arr.map(x=>x.rx/1048576),
    total: arr.map(x=>(x.total/1048576))
  });
  const d=mk((daily.items||[])), w=mk((weekly.items||[])), m=mk((monthly.items||[]));
  const makeCfg=(lbls, tx, rx)=>({
    type:'line',
    data:{ labels: lbls, datasets:[
      {label:'TX (MB)', data: tx, tension: .25},
      {label:'RX (MB)', data: rx, tension: .25}
    ]},
    options:{ responsive:true, maintainAspectRatio:false, plugins:{legend:{display:true}}, scales:{y:{beginAtZero:true}} }
  });
  const makeCfg2=(lbls, tot)=>({
    type:'bar',
    data:{ labels: lbls, datasets:[{label:'TOTAL (MB)', data: tot}]},
    options:{ responsive:true, maintainAspectRatio:false, plugins:{legend:{display:true}}, scales:{y:{beginAtZero:true}} }
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
  const cur = await api(`/api/admin/limits/${encodeURIComponent(sub)}`);
  const L = (cur&&cur.limits)||{};
  const html = `
    <div class="space-y-2">
      <div class="text-sm text-slate-600">단위: 숫자+접미사(B/KB/MB/GB/TB). 비워두면 제한 없음.</div>
      <div class="grid-auto">
        <div class="bg-slate-50 p-3 rounded-lg">
          <div class="mb-1 text-sm font-medium">일간</div>
          <input id="limDaily" class="w-full border rounded p-2" placeholder="예: 10GB" value="${L.daily?formatBytes(L.daily):''}">
        </div>
        <div class="bg-slate-50 p-3 rounded-lg">
          <div class="mb-1 text-sm font-medium">주간</div>
          <input id="limWeekly" class="w-full border rounded p-2" placeholder="예: 50GB" value="${L.weekly?formatBytes(L.weekly):''}">
        </div>
        <div class="bg-slate-50 p-3 rounded-lg">
          <div class="mb-1 text-sm font-medium">월간</div>
          <input id="limMonthly" class="w-full border rounded p-2" placeholder="예: 200GB" value="${L.monthly?formatBytes(L.monthly):''}">
        </div>
      </div>
    </div>`;
  const ok = await openCustomModal(`대역폭 제한 (${sub})`, html, '저장');
  if(!ok) return;
  const parseHuman = (s)=>{
    s=(s||'').trim(); if(!s) return 0;
    const m=s.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$/i);
    if(!m) return 0;
    let v=parseFloat(m[1]); const u=(m[2]||'B').toUpperCase();
    const mul = {B:1,KB:1024,MB:1048576,GB:1073741824,TB:1099511627776}[u]||1;
    return Math.round(v*mul);
  };
  const payload = {
    daily:   parseHuman(document.getElementById('limDaily').value),
    weekly:  parseHuman(document.getElementById('limWeekly').value),
    monthly: parseHuman(document.getElementById('limMonthly').value),
  };
  await fetch(`/api/admin/limits/${encodeURIComponent(sub)}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  showToast('제한이 저장되었습니다.','ok');
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
async function openClientsModal(sub){
  const d = await api(`/api/admin/clients/${encodeURIComponent(sub)}?days=30`);
  const cur = (d&&d.current_ips)||[];
  const hist = (d&&d.history)||[];

  const renderIpBadge = (ip)=> `<span class="badge ipbtn" data-ip="${ip}" title="세션 보기">${ip}</span>`;

  let html = `<div class="space-y-4">
    <div class="bg-white p-3 rounded-lg shadow">
      <div class="font-semibold mb-2">현재 접속 중 IP</div>
      <div>${cur.length? cur.map(renderIpBadge).join(' ') : '<span class="text-slate-400">없음</span>'}</div>
    </div>
    <div class="bg-white p-3 rounded-lg shadow">
      <div class="font-semibold mb-2">최근 접속 히스토리(일자별) — IP를 클릭하세요</div>
      <div class="space-y-2">`+
      (hist.length ? hist.map(r=>{
        const ips = (r.items||[]).map(it=>renderIpBadge(it.ip)).join(' ');
        return `<div><div class="text-sm text-slate-500 mb-1">${r.date}</div><div>${ips||'<span class="text-slate-400">없음</span>'}</div></div>`
      }).join('') : '<div class="text-slate-400">데이터 없음</div>') +
      `</div>
    </div>
  </div>`;

  const p = openCustomModal(`접속 IP (${sub})`, html, '닫기');
  document.getElementById('modalBody').querySelectorAll('.ipbtn').forEach(el=>{
    el.onclick = ()=> openIpSessions(sub, el.getAttribute('data-ip'));
  });
  await p;
}

function fmtDuration(ms){
  if(ms == null) return '-';
  const s = Math.max(0, Math.floor(ms/1000));
  const hh = Math.floor(s/3600), mm = Math.floor((s%3600)/60), ss = s%60;
  const pad = (n)=> n.toString().padStart(2,'0');
  if(hh>0) return `${pad(hh)}:${pad(mm)}:${pad(ss)}`;
  return `${pad(mm)}:${pad(ss)}`;
}

async function openIpSessions(sub, ip){
  const days = 30;
  const d = await api(`/api/admin/clients/${encodeURIComponent(sub)}/sessions?ip=${encodeURIComponent(ip)}&days=${days}`);
  const rows = [];
  (d.sessions||[]).forEach(day=>{
    (day.items||[]).forEach(sess=>{
      rows.push({date:day.date, start:sess.start||'', end:sess.end||''});
    });
  });
  rows.sort((a,b)=> (a.date+a.start).localeCompare(b.date+b.start));

  const now = new Date();
  const tr = rows.map(r=>{
    const st = r.start? new Date(r.start) : null;
    const en = r.end? new Date(r.end) : null;
    const dur = (st && en)? (en - st) : (st? (now - st) : null);
    const td = (x)=> `<td class="p-2 text-sm">${x||'-'}</td>`;
    return `<tr>
      ${td(r.date)}${td(r.start? r.start.replace('T',' ').replace('Z',' UTC') : '')}${td(r.end? r.end.replace('T',' ').replace('Z',' UTC') : '')}
      <td class="p-2 text-sm text-right">${fmtDuration(dur)}</td>
    </tr>`;
  }).join('');

  const html = `<div class="space-y-2">
    <div class="text-sm text-slate-600">IP: <b>${ip}</b> · 최근 ${days}일</div>
    <div class="overflow-x-auto">
      <table class="min-w-full text-sm border rounded">
        <thead class="bg-slate-100">
          <tr><th class="text-left p-2">날짜(UTC)</th><th class="text-left p-2">접속시간</th><th class="text-left p-2">나간시간</th><th class="text-right p-2">지속</th></tr>
        </thead>
        <tbody>${tr || `<tr><td class="p-2" colspan="4"><span class="text-slate-400">세션이 없습니다.</span></td></tr>`}</tbody>
      </table>
    </div>
  </div>`;
  await openCustomModal(`세션 상세 (${sub} / ${ip})`, html, '닫기');
}

/* ===== 전역 스케줄 저장 버튼 동작 ===== */
document.getElementById('saveSch').onclick = async ()=>{
  // 현재 전역 스케줄 불러와 모달에서 편집 → 저장
  const snap = await api('/api/tunnels');
  const cur = (snap && snap.access_schedules) || [];
  const items = await openScheduleModal('GLOBAL', cur);
  if(items===null) return;
  await fetch('/api/admin/schedule', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(items)});
  await renderGlobalScheduleList(); 
  showToast('전역 시간대가 저장되었습니다.','ok');
};

/* 초기/기타 액션 */
document.getElementById('refreshBtn').onclick = ()=>{ loadSnapshot(); showToast('새로고침 완료','ok'); };
document.getElementById('prevLogsBtn').onclick = loadLogListAndOpenFirst;
document.getElementById('prevLogsBtn2').onclick = loadLogListAndOpenFirst;
document.getElementById('openAgg').onclick = openAggModal;

document.getElementById('loadSel').onclick = async ()=>{
  const name = document.getElementById('logSel').value;
  if(!name) return showToast('선택된 로그가 없습니다.','warn');
  const r = await fetch('/api/logs/get?name='+encodeURIComponent(name));
  const text = await r.text();
  const pre=document.getElementById('logs'); pre.textContent = text; pre.scrollTop = pre.scrollHeight;
  showToast('로그 로드 완료','ok');
};
document.getElementById('saveIp').onclick = async ()=>{
  const raw=document.getElementById('ipAllow').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  await fetch('/api/admin/ip-allow', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({allow:arr})});
  showToast('저장되었습니다.','ok');
};
document.getElementById('saveTok').onclick = async ()=>{
  const raw=document.getElementById('tokens').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  await fetch('/api/admin/tokens', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({tokens:arr})});
  await loadSnapshot();
  await loadTokenMeta();
  showToast('저장되었습니다.','ok');
};
document.getElementById('saveDeny').onclick = async ()=>{
  const raw=document.getElementById('denyIp').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  await fetch('/api/admin/tunnel-ip-deny', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({deny:arr})});
  showToast('저장되었습니다.','ok');
};

/* 초기 로드 */
loadSnapshot();
loadLogList();
loadTokenMeta();
connectWS();
</script>
</body></html>
"""

@web.middleware
async def admin_ip_mw(request, handler):
    if request.path.startswith("/dashboard") or request.path.startswith("/api/") or request.path=="/admin_ws":
        ring_log(f"ADMIN access {client_ip(request)} {request.method} {request.path}")
    return await handler(request)

# ----- 로그인/로그아웃 -----
async def logout(request: web.Request) -> web.Response:
    resp = web.Response(status=401, text="Logged out")
    resp.headers["WWW-Authenticate"] = 'Basic realm="tunneler-admin-logout"'
    try: resp.del_cookie("admin_block", path="/")
    except Exception: pass
    return resp

async def login(request: web.Request) -> web.Response:
    resp = web.Response(status=401, text="Please login")
    resp.headers["WWW-Authenticate"] = 'Basic realm="tunneler-admin"'
    try: resp.del_cookie("admin_block", path="/")
    except Exception: pass
    return resp

@require_admin
async def dashboard_page(request: web.Request) -> web.Response:
    return web.Response(text=DASH_HTML, content_type="text/html")

@require_admin
async def admin_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=15.0)
    await ws.prepare(request)
    ADMIN_WSS.append(ws)
    await ws.send_json({"kind":"snapshot_logs","lines": LOG_RING[-MAX_LOG_LINES:]})
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
        "tokens": list(ALLOWED_TOKENS),
        "tunnel_ip_deny": STATE.get("tunnel_ip_deny", []),
        "tunnels": {
            k:{
                "tcp":{n:v["port"] for n,v in TUNNELS[k].get("tcp",{}).items()},
                "udp":{n:v["port"] for n,v in TUNNELS[k].get("udp",{}).items()},
                "tcp_streams": sum(len(v["streams"]) for v in TUNNELS[k].get("tcp",{}).values()),
                "udp_flows":   sum(len(v["flows"]) for v in TUNNELS[k].get("udp",{}).values()),
            } for k in TUNNELS.keys()
        }
    })

@require_admin
async def api_disconnect(request: web.Request) -> web.Response:
    sub=request.match_info["sub"]
    info=TUNNELS.get(sub); ok=False
    if info:
        ws=info.get("ws")
        with contextlib.suppress(Exception):
            await ws.close(message=b"admin_disconnect"); ok=True
    return web.json_response({"ok":ok})

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
    if token in ALLOWED_TOKENS:
        ALLOWED_TOKENS.remove(token)
        with open(TOK_FILE,"w",encoding="utf-8") as f:
            f.write(",".join(sorted(ALLOWED_TOKENS)))
        save_state(STATE)
        ring_log(f"ADMIN revoked token: {token}")
        broadcast({"kind":"log","line":f"[ADMIN] token revoked: {token}"})
        return web.json_response({"ok":True})
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
    ring_log(f"ADMIN updated tunnel deny IPs: {len(deny)} items")
    broadcast({"kind":"log","line":"[ADMIN] tunnel deny updated"})
    return web.json_response({"ok":True,"deny":deny})

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
@require_admin
async def api_clients(request: web.Request) -> web.Response:
    sub = request.match_info["sub"]
    days = max(1, min(365, int(request.query.get("days","30"))))
    current_ips = _current_ips_for(sub)
    hist_map = IP_HISTORY.get(sub, {})
    time_map = IP_TIMES.get(sub, {})
    keys = sorted(hist_map.keys())
    if days and keys:
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days-1)).strftime("%Y-%m-%d")
        keys = [k for k in keys if k >= cutoff]
    history = []
    for day in keys:
        ips = sorted(hist_map.get(day, []))
        items = []
        for ip in ips:
            times = (time_map.get(day, {}).get(ip, []) or [])
            items.append({"ip": ip, "times": times})
        history.append({"date": day, "items": items})
    return web.json_response({"ok":True, "sub":sub, "current_ips": current_ips, "history": history})

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
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days-1)).strftime("%Y-%m-%d")
        keys = [k for k in keys if k >= cutoff]
    out=[]
    for day in keys:
        items = ses.get(day, {}).get(ip, [])
        if not items: continue
        out.append({"date": day, "items": items})
    return web.json_response({"ok":True, "sub":sub, "ip":ip, "sessions": out})

# ===== 로그 파일 목록/조회 =====
@require_admin
async def api_logs_list(request: web.Request) -> web.Response:
    files = sorted([f for f in os.listdir(LOG_DIR) if f.startswith("server.log")], reverse=True)
    return web.json_response({"files": files})

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
        with open(path,"r",encoding="utf-8",errors="replace") as f:
            data = f.read()
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

        if not items and (total["tx"]==0 and total["rx"]==0): continue
        payload = {"kind":"bandwidth","ts": time.time(), "items": items, "total": total}
        broadcast(payload)

# = 앱 구성 =
async def make_app() -> web.Application:
    app = web.Application(client_max_size=64*1024*1024, middlewares=[admin_ip_mw])
    app.add_routes([
        web.get("/_ws", ws_handler),

        # 로그인/로그아웃 & 대시보드
        web.get("/login", login),
        web.get("/dashboard", dashboard_page),
        web.get("/logout", logout),
        web.get("/admin_ws", admin_ws),

        # 관리/조회 API
        web.get ("/api/tunnels", api_tunnels),
        web.post("/api/tunnels/{sub}/disconnect", api_disconnect),
        web.post("/api/admin/ip-allow", api_set_ip_allow),
        web.post("/api/admin/tokens", api_set_tokens),
        web.get ("/api/admin/tokens/meta", api_token_meta),
        web.post("/api/admin/token/revoke", api_token_revoke),
        web.post("/api/admin/logs/clear", api_logs_clear),
        web.post("/api/admin/schedule", api_schedule_set),
        web.get ("/api/admin/schedule/{sub}",  api_tunnel_schedule_get),
        web.post("/api/admin/schedule/{sub}",  api_tunnel_schedule_set),
        web.post("/api/admin/tunnel-ip-deny", api_set_tunnel_deny),

        # 집계/제한
        web.get ("/api/stats/usage", api_usage),
        web.get ("/api/stats/usage/all", api_usage_all),
        web.get ("/api/admin/limits/{sub}", api_limits_get),
        web.post("/api/admin/limits/{sub}", api_limits_set),

        # 접속 IP / 세션
        web.get ("/api/admin/clients/{sub}", api_clients),
        web.get ("/api/admin/clients/{sub}/sessions", api_ip_sessions),

        # 로그 파일 목록/조회
        web.get("/api/logs/list", api_logs_list),
        web.get("/api/logs/get", api_logs_get),

        # 공개 HTTP 프록시
        web.route("*","/{tail:.*}", public_http_handler),
    ])
    app["bw_task"] = asyncio.create_task(bw_loop())
    return app

def main():
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
