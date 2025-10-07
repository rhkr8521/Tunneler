#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio, base64, json, logging, os, signal, socket, uuid, ipaddress, datetime, time
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

# 실시간 대역폭(초당 누적) — 터널별과 전체 ( UI에서 MB/s로 표시)
_bw_counters: Dict[str, Dict[str, int]] = {}  # subdomain -> {"tx":..(client->srv), "rx":..(srv->client)}
_bw_total: Dict[str, int] = {"tx":0, "rx":0}  # 전터널 합(초당)

def _bw_acc(sub: str, key: str, n: int):
    n = max(0, int(n))
    c = _bw_counters.setdefault(sub or "_", {"tx":0,"rx":0})
    c[key] = c.get(key,0) + n
    _bw_total[key] = _bw_total.get(key,0) + n

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

# 관리자 대시보드 Basic Auth
ADMIN_USER = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "")

# 관리자/서버 상태 파일
STATE_FILE = os.getenv("ADMIN_STATE_FILE", "/opt/tunneler/admin_state.json")
def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            "admin_ip_allow": [],
            "access_schedules": [],       # (전체 공용)
            "per_tunnel_schedules": {},   # (터널별) {sub:[{days,start,end},...]}
            "token_meta": {},             # token -> {"last_ip":"1.2.3.4","last_at":"2025-10-07T03:21:00Z"}
            "tunnel_ip_deny": []          # 외부(공개포트) 접근 차단 IP/CIDR 리스트
        }
    try:
        with open(STATE_FILE,"r",encoding="utf-8") as f:
            s=json.load(f)
            s.setdefault("admin_ip_allow",[])
            s.setdefault("access_schedules",[])
            s.setdefault("per_tunnel_schedules",{})
            s.setdefault("token_meta",{})
            s.setdefault("tunnel_ip_deny",[])
            return s
    except Exception:
        return {"admin_ip_allow": [], "access_schedules": [], "per_tunnel_schedules": {}, "token_meta": {}, "tunnel_ip_deny": []}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE,"w",encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

STATE = load_state()

# 포트 범위/리소스
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
    host = host.split(":")[0]
    parts = host.split(".")
    return parts[0] if len(parts) >= 3 else None

def client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff: return xff.split(",")[0].strip()
    return request.remote or "0.0.0.0"

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
                if ip_obj in ipaddress.ip_network(rule, strict=False):
                    return True
            else:
                if ip == rule:
                    return True
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
                if ip_obj in ipaddress.ip_network(rule, strict=False):
                    return True
            else:
                if ip == rule:
                    return True
        except Exception:
            continue
    return False

# ===== 접속 허용 시간대 (전역/터널별) =====
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
    if not rules:
        return True
    if now is None:
        now = datetime.datetime.now()
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
            else:  # 야간 넘김
                if cur >= smin or cur <= emin: return True
    return False

def access_allowed_for(sub: Optional[str]) -> bool:
    rules = []
    if sub:
        rules = (STATE.get("per_tunnel_schedules") or {}).get(sub, [])
    if not rules:
        rules = STATE.get("access_schedules", [])
    return _time_in_ranges(rules)

# ===== 토큰 메타(마지막 사용 IP/시간) =====
def touch_token_meta(token: str, ip: str):
    if not token: return
    meta = STATE.setdefault("token_meta", {})
    meta[token] = {
        "last_ip": ip,
        "last_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
    }
    save_state(STATE)

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
        try: ADMIN_WSS.remove(ws)
        except ValueError: pass

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
        if not parse_basic_auth(request):
            resp = web.Response(status=401, text="Unauthorized")
            resp.headers["WWW-Authenticate"] = 'Basic realm="tunneler-admin"'
            return resp
        return await handler(request)
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
    peer = request.remote
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

                    # 터널별 시간대 체크
                    if not access_allowed_for(candidate):
                        await ws.send_json({"type":"register_result","ok":False,"reason":"time_forbidden"}); continue

                    ok, reason = verify_auth(auth_token)
                    if not ok:
                        await ws.send_json({"type":"register_result","ok":False,"reason":reason}); continue

                    touch_token_meta(auth_token, peer or "")

                    if candidate in TUNNELS:
                        try: await TUNNELS[candidate]["ws"].close(message=b"replaced")
                        except Exception: pass

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
                            if tunnel_ip_blocked(rip) or not access_allowed_for(_sub):
                                try: writer.close(); await writer.wait_closed()
                                except Exception: pass
                                return
                            sid=str(uuid.uuid4())
                            TUNNELS[_sub]["tcp"][_name]["streams"][sid]={"reader":reader,"writer":writer}
                            sock=writer.get_extra_info("socket")
                            if sock is not None:
                                import socket as pysock
                                try: sock.setsockopt(pysock.IPPROTO_TCP, pysock.TCP_NODELAY, 1)
                                except Exception: pass
                            await ws.send_json({"type":"tcp_open","name":_name,"stream_id":sid})
                            ring_log(f"TCP OPEN {_sub}/{_name}/{sid} from {rip}")

                            async def pump_up():
                                try:
                                    while True:
                                        if not access_allowed_for(_sub): break
                                        chunk=await reader.read(65536)
                                        if not chunk: break
                                        _bw_acc(_sub,"rx",len(chunk))  # 외부->서버->클라
                                        await ws.send_json({"type":"tcp_data","stream_id":sid,"b64":b64e(chunk)})
                                except Exception: pass
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
                                if tunnel_ip_blocked(rip) or not access_allowed_for(subdomain):
                                    return
                                if addr not in flows:
                                    fid=str(uuid.uuid4())
                                    flows[addr]={"flow_id":fid,"last":loop.time()}
                                    asyncio.create_task(ws.send_json({"type":"udp_open","name":name,"flow_id":fid}))
                                flows[addr]["last"]=loop.time()
                                fid=flows[addr]["flow_id"]
                                _bw_acc(subdomain or "", "rx", len(data))
                                asyncio.create_task(ws.send_json({"type":"udp_data","flow_id":fid,"b64":b64e(data)}))
                        transport, protocol = await loop.create_datagram_endpoint(lambda: UdpProto(), local_addr=("0.0.0.0",port))
                        INUSE_UDP.add(port)
                        async def gc():
                            while True:
                                await asyncio.sleep(5)
                                now=loop.time()
                                for k,v in list(flows.items()):
                                    if now - v["last"] > FLOW_IDLE:
                                        fid=v["flow_id"]; flows.pop(k,None)
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
                                    if access_allowed_for(subdomain):
                                        _bw_acc(subdomain, "tx", len(payload))  # 클라->서버->원격
                                        st["writer"].write(payload); await st["writer"].drain()
                                except Exception: pass
                                break

                elif mtype == "tcp_close":
                    sid=data["stream_id"]
                    if subdomain:
                        for t in TUNNELS[subdomain]["tcp"].values():
                            st=t["streams"].pop(sid, None)
                            if st:
                                try: st["writer"].close()
                                except Exception: pass
                                break

                elif mtype == "udp_data":
                    fid=data["flow_id"]; payload=b64d(data.get("b64"))
                    if subdomain:
                        for ud in TUNNELS[subdomain]["udp"].values():
                            for addr,meta in ud["flows"].items():
                                if meta["flow_id"]==fid:
                                    if access_allowed_for(subdomain):
                                        _bw_acc(subdomain, "tx", len(payload))  # 클라->서버->외부
                                        ud["transport"].sendto(payload, addr)
                                        meta["last"]=asyncio.get_running_loop().time()
                                    break

                elif mtype == "udp_close":
                    fid=data["flow_id"]
                    if subdomain:
                        for ud in TUNNELS[subdomain]["udp"].values():
                            for addr,meta in list(ud["flows"].items()):
                                if meta["flow_id"]==fid:
                                    ud["flows"].pop(addr,None); break

                elif mtype == "proxy_response":
                    rid=data.get("id")
                    fut=PENDING.pop(rid, None)
                    if fut and not fut.done():
                        fut.set_result(data)

            elif msg.type == WSMsgType.ERROR:
                logger.warning("WS error: %s", ws.exception()); ring_log(f"WS error: {ws.exception()}")

    finally:
        for sub, info in list(TUNNELS.items()):
            if info.get("ws") is ws:
                for t in info.get("tcp",{}).values():
                    try: t["server"].close()
                    except Exception: pass
                    INUSE_TCP.discard(t["port"])
                for u in info.get("udp",{}).values():
                    try: u["transport"].close()
                    except Exception: pass
                    INUSE_UDP.discard(u["port"])
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

    # 터널별 시간대 / 접근 차단 IP
    ip = client_ip(request)
    host = request.headers.get("Host","")
    sub = extract_subdomain(host) or request.rel_url.query.get("x-subdomain")
    if not sub or sub not in TUNNELS:
        return web.Response(status=404, text="No tunnel for this host")
    if tunnel_ip_blocked(ip) or not access_allowed_for(sub):
        return web.Response(status=403, text="forbidden")

    ws: web.WebSocketResponse = TUNNELS[sub]["ws"]
    rid=str(uuid.uuid4())
    body=await request.read()
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
    _bw_acc(sub, "rx", len(body_bytes))  # 서버→클라 방향(응답 본문)
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
</head>
<body class="bg-slate-50 text-slate-800">
<div class="max-w-7xl mx-auto p-4">
  <header class="flex flex-col sm:flex-row gap-2 sm:items-center sm:justify-between py-3">
    <h1 class="text-2xl font-bold">Tunneler 대시보드</h1>
    <div class="flex items-center gap-2">
      <a href="/logout" class="px-3 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 text-sm">로그아웃</a>
      <div class="text-sm text-slate-500" id="rangeInfo"></div>
    </div>
  </header>

  <section class="grid md:grid-cols-5 gap-3 my-3" id="stats">
    <div class="bg-white rounded-xl shadow p-4">
      <div class="text-sm text-slate-500">활성 서브도메인</div>
      <div class="text-2xl font-bold mt-1" id="statSubs">-</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4">
      <div class="text-sm text-slate-500">할당 TCP 포트 수</div>
      <div class="text-2xl font-bold mt-1" id="statTCP">-</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4">
      <div class="text-sm text-slate-500">할당 UDP 포트 수</div>
      <div class="text-2xl font-bold mt-1" id="statUDP">-</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4">
      <div class="text-sm text-slate-500">총 Up (MB/s)</div>
      <div class="text-2xl font-bold mt-1" id="statUp">0.00</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4">
      <div class="text-sm text-slate-500">총 Down (MB/s)</div>
      <div class="text-2xl font-bold mt-1" id="statDown">0.00</div>
    </div>
  </section>

  <section class="mt-5">
    <div class="flex items-center justify-between mb-2">
      <h2 class="text-lg font-semibold">활성 터널</h2>
      <div class="flex gap-2">
        <button id="prevLogsBtn" class="px-3 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300">이전 로그 보기</button>
        <button id="refreshBtn" class="px-3 py-1.5 rounded-lg bg-indigo-600 text-white hover:bg-indigo-700">수동 새로고침</button>
      </div>
    </div>
    <div id="list" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3"></div>
  </section>

  <section class="mt-8 grid md:grid-cols-2 gap-6">
    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">대시보드 IP 제한</h3>
      <p class="text-sm text-slate-500 mb-2">허용할 IP 또는 CIDR(쉼표 구분). 비워두면 제한 없음.</p>
      <input id="ipAllow" class="w-full border rounded-lg p-2 mb-2" placeholder="예: 1.2.3.4, 10.0.0.0/24"/>
      <button id="saveIp" class="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-700 text-white">저장</button>
    </div>

    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">접속 허용 시간대(전역)</h3>
      <p class="text-sm text-slate-500 mb-2">예) mon-fri 09:00~18:00, sat-sun 10:00~16:00</p>
      <div class="space-y-2" id="schList"></div>
      <div class="flex gap-2 mt-2">
        <input id="schDays" class="flex-1 border rounded-lg p-2" placeholder="days (all|mon-fri|sat-sun|mon,tue,...)">
        <input id="schStart" class="w-32 border rounded-lg p-2" placeholder="start HH:MM">
        <input id="schEnd" class="w-32 border rounded-lg p-2" placeholder="end HH:MM">
        <button id="addSch" class="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-700 text-white">추가</button>
      </div>
      <button id="saveSch" class="mt-2 px-3 py-1.5 rounded bg-sky-700 hover:bg-sky-800 text-white">저장</button>
    </div>
  </section>

  <section class="mt-8 grid md:grid-cols-2 gap-6">
    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">클라이언트 토큰(화이트리스트)</h3>
      <p class="text-sm text-slate-500 mb-2">쉼표로 구분. 비워두면 인증 없이 허용(개발용).</p>
      <input id="tokens" class="w-full border rounded-lg p-2 mb-2" placeholder="예: AAA, BBB, TEAM-ALPHA"/>
      <button id="saveTok" class="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-700 text-white">저장</button>
      <h4 class="font-semibold mt-4 mb-1">토큰 마지막 사용 / 빠른 무효화</h4>
      <div id="tokMeta" class="text-sm"></div>
    </div>

    <div class="bg-white rounded-2xl shadow p-4">
      <h3 class="font-semibold mb-2">터널 접근 차단 IP/CIDR</h3>
      <p class="text-sm text-slate-500 mb-2">외부 사용자가 공개 포트로 접근하는 것을 차단. 쉼표 구분.</p>
      <input id="denyIp" class="w-full border rounded-lg p-2 mb-2" placeholder="예: 203.0.113.5, 10.0.0.0/8">
      <button id="saveDeny" class="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-700 text-white">저장</button>
    </div>
  </section>

  <section class="mt-8">
    <h3 class="font-semibold mb-2">실시간 대역폭(초당)</h3>
    <div class="grid md:grid-cols-3 gap-3 mb-2">
      <div class="bg-white rounded-xl shadow p-4">
        <div class="text-sm text-slate-500">총 Up (MB/s)</div>
        <div class="text-2xl font-bold mt-1" id="totalUp">0.00</div>
      </div>
      <div class="bg-white rounded-xl shadow p-4">
        <div class="text-sm text-slate-500">총 Down (MB/s)</div>
        <div class="text-2xl font-bold mt-1" id="totalDown">0.00</div>
      </div>
      <div class="bg-white rounded-xl shadow p-4">
        <div class="text-sm text-slate-500">활성 터널 수(초당 갱신)</div>
        <div class="text-2xl font-bold mt-1" id="bwSubs">0</div>
      </div>
    </div>
    <div class="overflow-x-auto">
      <table class="min-w-full text-sm border rounded" id="bwTable">
        <thead class="bg-slate-100">
          <tr><th class="text-left p-2">Subdomain</th><th class="text-left p-2">Up (MB/s)</th><th class="text-left p-2">Down (MB/s)</th></tr>
        </thead>
        <tbody id="bwBody"></tbody>
      </table>
    </div>
  </section>

  <section class="mt-8">
    <div class="flex items-center justify-between mb-2">
      <h3 class="font-semibold">서버 로그(최근)</h3>
      <div class="flex gap-2">
        <select id="logSel" class="border rounded p-1 text-sm"></select>
        <button id="loadSel" class="px-3 py-1.5 rounded bg-slate-200 hover:bg-slate-300 text-sm">선택 로그 보기</button>
        <button id="prevLogsBtn" class="px-3 py-1.5 rounded bg-slate-200 hover:bg-slate-300">이전 로그 보기</button>
        <button id="clearLog" class="px-3 py-1.5 rounded bg-slate-200 hover:bg-slate-300">지우기</button>
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
function el(tag, cls="", html=""){ const e=document.createElement(tag); if(cls) e.className=cls; if(html) e.innerHTML=html; return e; }
async function api(path, opts={}){ const r=await fetch(path, opts); if(r.status===401){ location.reload(); return; } return r.json(); }

function toMBs(v){ return (v/1048576).toFixed(2); } // Bytes/s -> MB/s

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
  } else {
    alert('표시할 로그가 없습니다.');
  }
}

async function loadSnapshot(){
  const d = await api('/api/tunnels'); if(!d) return;
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
    const card=el('div','bg-white rounded-2xl shadow p-4 flex flex-col gap-3');
    const h=el('div','flex items-center justify-between');
    h.appendChild(el('div','text-lg font-semibold', sub));

    const btnWrap=el('div','flex gap-2');
    const scheduleBtn=document.createElement('button');
    scheduleBtn.className='px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-700 text-white text-sm';
    scheduleBtn.textContent='시간대';
    scheduleBtn.onclick = async ()=>{
      const cur = await api(`/api/admin/schedule/${sub}`);
      const curStr = (cur.items||[]).map(x=>`${x.days||'all'} ${x.start||'00:00'}~${x.end||'23:59'}`).join(', ');
      const v = prompt(`현재 규칙: ${curStr}\n형식: days start~end 을 쉼표로 여러개. 예) mon-fri 09:00~18:00, sat-sun 10:00~16:00\n비우면 삭제`, curStr);
      if (v === null) return;
      const items = (v.trim()==='')
        ? []
        : v.split(',').map(s=>s.trim()).filter(Boolean).map(s=>{
            const m = s.match(/^(\S+)\s+(\d{2}:\d{2})~(\d{2}:\d{2})$/);
            if(!m) return null;
            return {days:m[1], start:m[2], end:m[3]};
          }).filter(Boolean);
      await fetch(`/api/admin/schedule/${sub}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(items)});
      alert('저장되었습니다.');
    };
    btnWrap.appendChild(scheduleBtn);

    const disBtn=document.createElement('button');
    disBtn.className='px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-700 text-white text-sm';
    disBtn.textContent='Disconnect';
    disBtn.onclick=async()=>{ if(!confirm(`${sub} 터널을 종료할까요?`)) return; await fetch(`/api/tunnels/${sub}/disconnect`,{method:'POST'}); };
    btnWrap.appendChild(disBtn);

    h.appendChild(btnWrap);
    card.appendChild(h);
    const sec1=el('div','text-sm'); sec1.innerHTML='<span class="font-medium">TCP</span><div class="mt-1 flex flex-wrap gap-1">'+(tcpList||'<span class="text-slate-400">없음</span>')+'</div>';
    const sec2=el('div','text-sm'); sec2.innerHTML='<span class="font-medium">UDP</span><div class="mt-1 flex flex-wrap gap-1">'+(udpList||'<span class="text-slate-400">없음</span>')+'</div>';
    card.appendChild(sec1); card.appendChild(sec2);
    list.appendChild(card);
  });

  document.getElementById('ipAllow').value = (d.admin_ip_allow||[]).join(', ');
  document.getElementById('tokens').value = (d.tokens||[]).join(', ');
  document.getElementById('denyIp').value = (d.tunnel_ip_deny||[]).join(', ');

  // 전역 스케줄 렌더
  const sch = d.access_schedules||[];
  const wrap = document.getElementById('schList'); wrap.innerHTML='';
  sch.forEach((s,idx)=>{
    const row = el('div','flex items-center gap-2');
    row.innerHTML = `
      <span class="px-2 py-1 bg-slate-100 rounded">${s.days||'all'}</span>
      <span class="px-2 py-1 bg-slate-100 rounded">${s.start||'00:00'} ~ ${s.end||'23:59'}</span>
      <button class="px-2 py-1 text-xs rounded bg-rose-100 hover:bg-rose-200" data-idx="${idx}">삭제</button>`;
    row.querySelector('button').onclick=()=>{ sch.splice(idx,1); document.getElementById('saveSch').dataset.payload = JSON.stringify(sch); loadSnapshot(); };
    wrap.appendChild(row);
  });
  document.getElementById('saveSch').dataset.payload = JSON.stringify(sch);
}

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
      <td class="py-1 pr-2"><button class="px-2 py-1 rounded bg-rose-600 hover:bg-rose-700 text-white" data-token="${r.token}">무효화</button></td>`;
    tr.querySelector('button').onclick=async(e)=>{
      if(!confirm('해당 토큰을 즉시 무효화할까요?')) return;
      const tok = e.target.getAttribute('data-token');
      await fetch('/api/admin/token/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tok})});
      await loadSnapshot();
    };
    tb.appendChild(tr);
  });
  box.appendChild(tbl);
}

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
        // Bytes/s -> MB/s
        const upMB  = toMBs(tot.tx||0);
        const downMB= toMBs(tot.rx||0);
        document.getElementById('totalUp').textContent = upMB;
        document.getElementById('totalDown').textContent = downMB;
        document.getElementById('statUp').textContent = upMB;
        document.getElementById('statDown').textContent = downMB;
        document.getElementById('bwSubs').textContent = Object.keys(items).length;

        tbody.innerHTML='';
        Object.keys(items).sort().forEach(sub=>{
          const v=items[sub]||{};
          const tr=document.createElement('tr');
          tr.innerHTML = `<td class="p-2">${sub}</td><td class="p-2">${toMBs(v.tx||0)}</td><td class="p-2">${toMBs(v.rx||0)}</td>`;
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

document.getElementById('refreshBtn').onclick = loadSnapshot;
document.getElementById('prevLogsBtn').onclick = loadLogListAndOpenFirst;

document.getElementById('loadSel').onclick = async ()=>{
  const name = document.getElementById('logSel').value;
  if(!name) return;
  const r = await fetch('/api/logs/get?name='+encodeURIComponent(name));
  const text = await r.text();
  const pre=document.getElementById('logs'); pre.textContent = text; pre.scrollTop = pre.scrollHeight;
};

document.getElementById('saveIp').onclick = async ()=>{
  const raw=document.getElementById('ipAllow').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  await fetch('/api/admin/ip-allow', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({allow:arr})});
  alert('저장되었습니다.');
};

document.getElementById('saveTok').onclick = async ()=>{
  const raw=document.getElementById('tokens').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  await fetch('/api/admin/tokens', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({tokens:arr})});
  await (async()=>{const tm=await api('/api/admin/tokens/meta');})(); // no-op refresh
  await loadSnapshot();
  alert('저장되었습니다.');
};

document.getElementById('saveDeny').onclick = async ()=>{
  const raw=document.getElementById('denyIp').value.trim();
  const arr = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean) : [];
  await fetch('/api/admin/tunnel-ip-deny', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({deny:arr})});
  alert('저장되었습니다.');
};

document.getElementById('clearLog').onclick = async ()=>{
  await fetch('/api/admin/logs/clear',{method:'POST'}); document.getElementById('logs').textContent='';
};

document.getElementById('addSch').onclick = ()=>{
  const d=document.getElementById('schDays').value.trim()||'all';
  const s=document.getElementById('schStart').value.trim()||'00:00';
  const e=document.getElementById('schEnd').value.trim()||'23:59';
  const cur=JSON.parse(document.getElementById('saveSch').dataset.payload||'[]');
  cur.push({days:d,start:s,end:e});
  document.getElementById('saveSch').dataset.payload = JSON.stringify(cur);
  document.getElementById('schDays').value=''; document.getElementById('schStart').value=''; document.getElementById('schEnd').value='';
  loadSnapshot();
};
document.getElementById('saveSch').onclick = async (ev)=>{
  const payload = ev.target.dataset.payload || '[]';
  await fetch('/api/admin/schedule', {method:'POST', headers:{'Content-Type':'application/json'}, body:payload});
  alert('저장되었습니다.');
  loadSnapshot();
};

loadSnapshot();
loadLogList();   // 셀렉트 초기 채우기
connectWS();
</script>
</body></html>
"""

@web.middleware
async def admin_ip_mw(request, handler):
    if request.path.startswith("/dashboard") or request.path.startswith("/api/") or request.path=="/admin_ws":
        ring_log(f"ADMIN access {client_ip(request)} {request.method} {request.path}")
    return await handler(request)

# ----- 로그아웃(브라우저 Basic Auth 캐시 무력화) -----
async def logout(request: web.Request) -> web.Response:
    resp = web.Response(status=401, text="Logged out")
    resp.headers["WWW-Authenticate"] = 'Basic realm="tunneler-admin-logout"'
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
        try: ADMIN_WSS.remove(ws)
        except ValueError: pass
    return ws

# ====== 대시보드/관리 API ======
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
        try: await ws.close(message=b"admin_disconnect"); ok=True
        except Exception: ok=False
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
    toks = body.get("tokens") or []
    os.makedirs(os.path.dirname(TOK_FILE), exist_ok=True)
    with open(TOK_FILE,"w",encoding="utf-8") as f:
        f.write(",".join(toks))
    ALLOWED_TOKENS = set(load_tokens())
    meta = STATE.setdefault("token_meta", {})
    for tk in list(meta.keys()):
        if tk not in ALLOWED_TOKENS:
            meta.pop(tk, None)
    save_state(STATE)
    ring_log(f"ADMIN updated tokens: {len(ALLOWED_TOKENS)} tokens")
    broadcast({"kind":"log","line":"[ADMIN] tokens updated"})
    return web.json_response({"ok":True,"tokens":list(ALLOWED_TOKENS)})

@require_admin
async def api_token_meta(request: web.Request) -> web.Response:
    items=[]
    meta = STATE.get("token_meta", {})
    for tk in sorted(ALLOWED_TOKENS):
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
        STATE.setdefault("token_meta", {}).pop(token, None)
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

# --- 터널별 스케줄 ---
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
    deny = body.get("deny") or []
    STATE["tunnel_ip_deny"] = deny
    save_state(STATE)
    ring_log(f"ADMIN updated tunnel deny IPs: {len(deny)} items")
    broadcast({"kind":"log","line":"[ADMIN] tunnel deny updated"})
    return web.json_response({"ok":True,"deny":deny})

# ===== 일별 로그 파일 목록/조회 (안전 처리) =====
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
        # FIX: charset은 content_type에 넣지 않는다.
        return web.Response(status=200, text=data, content_type="text/plain", charset="utf-8")
    except PermissionError:
        return web.Response(status=403, text="forbidden")
    except Exception as e:
        logger.exception("api_logs_get failed: %s", e)
        return web.Response(status=500, text="internal error")

# ===== 대역폭 브로드캐스트 루프 =====
async def bw_loop():
    global _bw_counters, _bw_total
    while True:
        await asyncio.sleep(1.0)
        items = _bw_counters
        total = _bw_total
        _bw_counters = {}
        _bw_total = {"tx":0,"rx":0}
        if not items and (total["tx"]==0 and total["rx"]==0):
            continue
        payload = {"kind":"bandwidth","ts": time.time(), "items": items, "total": total}
        broadcast(payload)

# = 앱 구성 =
async def make_app() -> web.Application:
    app = web.Application(client_max_size=64*1024*1024, middlewares=[admin_ip_mw])
    app.add_routes([
        web.get("/_ws", ws_handler),

        # 대시보드/관리
        web.get("/dashboard", dashboard_page),
        web.get("/logout", logout),
        web.get("/admin_ws", admin_ws),
        web.get("/api/tunnels", api_tunnels),
        web.post("/api/tunnels/{sub}/disconnect", api_disconnect),
        web.post("/api/admin/ip-allow", api_set_ip_allow),
        web.post("/api/admin/tokens", api_set_tokens),
        web.get("/api/admin/tokens/meta", api_token_meta),
        web.post("/api/admin/token/revoke", api_token_revoke),
        web.post("/api/admin/logs/clear", api_logs_clear),
        web.post("/api/admin/schedule", api_schedule_set),
        web.get ("/api/admin/schedule/{sub}",  api_tunnel_schedule_get),
        web.post("/api/admin/schedule/{sub}",  api_tunnel_schedule_set),
        web.post("/api/admin/tunnel-ip-deny", api_set_tunnel_deny),

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
        try: loop.add_signal_handler(s, _stop)
        except NotImplementedError: pass
    loop.run_until_complete(stop.wait())
    logger.info("Shutting down...")
    ring_log("SERVER STOP")
    try:
        app["bw_task"].cancel()
    except Exception:
        pass
    loop.run_until_complete(runner.cleanup())
    loop.close()

if __name__=="__main__":
    main()
