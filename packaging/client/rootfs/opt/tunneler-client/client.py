#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tunneler Client
- 제어/데이터 채널: WebSocket
- 기능:
  * TCP 터널: server의 할당 포트 <-> local name=HOST:PORT
  * UDP 터널: server의 flow_id <-> local name=HOST:PORT (flow별 소켓)
  * HTTP 프록시: HTTP_BASE가 있으면 / (대시보드/서브도메인용) 요청을 로컬로 프록시
- 인자:
  client.py WS_URL SUBDOMAIN TOKEN [--http URL] [--tcp name=host:port]* [--udp name=host:port]*
  예) python client.py ws://example.com/_ws mybox SECRET \
        --tcp ssh=127.0.0.1:22 --udp dns=127.0.0.1:53 --http http://127.0.0.1:8080
"""
import asyncio
import base64
import json
import sys
import signal
from typing import Dict, Tuple, Optional

import aiohttp

def usage():
    print("Usage: client.py WS_URL SUBDOMAIN TOKEN [--http URL] [--tcp name=host:port]* [--udp name=host:port]*")
    sys.exit(1)

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

class TCPMap:
    def __init__(self, name: str, host: str, port: int):
        self.name = name; self.host = host; self.port = port

class UDPFlow:
    def __init__(self, name: str, sock: asyncio.DatagramTransport):
        self.name = name
        self.sock = sock

class UDPMap:
    def __init__(self, name: str, host: str, port: int):
        self.name = name; self.host = host; self.port = port
        # flow_id -> UDPFlow
        self.flows: Dict[str, UDPFlow] = {}

async def open_udp_flow(loop: asyncio.AbstractEventLoop, name: str, target_host: str, target_port: int,
                        on_recv):
    """
    flow용 UDP 소켓을 만들고 target_host:target_port 로만 송수신.
    on_recv(data: bytes) 콜백 호출.
    """
    class CliUDP(asyncio.DatagramProtocol):
        def connection_made(self, transport: asyncio.DatagramTransport):
            self.transport = transport
        def datagram_received(self, data: bytes, addr):
            asyncio.create_task(on_recv(data))
        def error_received(self, exc): pass

    # 연결지향처럼 사용할 목적지
    connect_addr = (target_host, target_port)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: CliUDP(), remote_addr=connect_addr
    )
    return transport  # DatagramTransport

async def run_client(ws_url: str, subdomain: str, token: str,
                     http_base: Optional[str],
                     tcp_map: Dict[str, TCPMap],
                     udp_map: Dict[str, UDPMap]):
    """
    WS 연결 유지 + 메시지 핸들링 루프 (자동 재연결)
    """
    backoff = 1.0
    stop_event = asyncio.Event()

    def handle_sig():
        stop_event.set()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, handle_sig)
        loop.add_signal_handler(signal.SIGTERM, handle_sig)
    except NotImplementedError:
        pass

    while not stop_event.is_set():
        try:
            timeout = aiohttp.ClientTimeout(total=None, sock_read=None, sock_connect=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(ws_url, heartbeat=20) as ws:
                    print(f"[INFO] WS connected to {ws_url}")
                    # register
                    reg = {
                        "type": "register",
                        "subdomain": subdomain,
                        "auth_token": token,
                        "tcp_configs": [{"name": m.name, "remote_port": 0} for m in tcp_map.values()],
                        "udp_configs": [{"name": m.name, "remote_port": 0} for m in udp_map.values()],
                    }
                    await ws.send_json(reg)

                    # state
                    tcp_streams: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
                    # udp_map[name].flows[flow_id] -> UDPFlow 로 관리

                    # proxy helper (HTTP)
                    async def do_proxy(req: dict) -> dict:
                        if not http_base:
                            return {"status": 502, "headers": [], "body_b64": b64e(b"HTTP base not configured")}
                        method = req.get("method", "GET")
                        path_qs = req.get("path_qs", "/")
                        headers = req.get("headers", [])
                        body = b64d(req.get("body_b64", ""))

                        # destination URL
                        if http_base.endswith("/") and path_qs.startswith("/"):
                            url = http_base[:-1] + path_qs
                        else:
                            url = http_base + path_qs

                        hdict = {}
                        for k, v in headers:
                            lk = k.lower()
                            if lk in ("host", "content-length", "connection", "upgrade"):
                                continue
                            hdict[k] = v

                        try:
                            async with aiohttp.ClientSession() as s:
                                async with s.request(method, url, headers=hdict, data=body) as r:
                                    rb = await r.read()
                                    resp_headers = [(k, v) for k, v in r.headers.items()]
                                    return {"status": r.status, "headers": resp_headers, "body_b64": b64e(rb)}
                        except Exception as e:
                            return {"status": 502, "headers": [], "body_b64": b64e(str(e).encode())}

                    # 메인 메시지 루프
                    assigned_once = False

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = json.loads(msg.data)
                            except Exception:
                                continue
                            mtype = data.get("type")

                            if mtype == "register_result":
                                if data.get("ok"):
                                    # 서버에서 할당 받은 포트 목록
                                    tcp_assigned = data.get("tcp_assigned", [])
                                    udp_assigned = data.get("udp_assigned", [])
                                    print("[OK] 등록 성공. 원격 포트 할당:")
                                    if tcp_assigned:
                                        print("  TCP:", ", ".join(f"{e['name']}={e['remote_port']}" for e in tcp_assigned))
                                    if udp_assigned:
                                        print("  UDP:", ", ".join(f"{e['name']}={e['remote_port']}" for e in udp_assigned))
                                    if not assigned_once:
                                        assigned_once = True
                                        print("관리자 대시보드에서 현재 할당 포트를 확인하세요.")
                                else:
                                    print(f"[ERR] register failed: {data.get('reason')}")
                                    await asyncio.sleep(3)
                                    break

                            elif mtype == "proxy_request":
                                rid = data.get("id")
                                req = data.get("request", {})
                                resp = await do_proxy(req)
                                await ws.send_json({"type": "proxy_response", "id": rid, **resp})

                            elif mtype == "tcp_open":
                                name = data["name"]; sid = data["stream_id"]
                                if name not in tcp_map:
                                    # 알 수 없는 name: 바로 종료 통지
                                    await ws.send_json({"type": "tcp_close", "stream_id": sid, "who": "client"})
                                    continue
                                target = tcp_map[name]
                                try:
                                    reader, writer = await asyncio.open_connection(target.host, target.port)
                                except Exception as e:
                                    # 접속 실패 → 바로 close
                                    await ws.send_json({"type": "tcp_close", "stream_id": sid, "who": "client"})
                                    continue
                                tcp_streams[sid] = (reader, writer)

                                async def pump_local_to_ws(_sid=sid, _reader=reader):
                                    try:
                                        while True:
                                            chunk = await _reader.read(65536)
                                            if not chunk:
                                                break
                                            await ws.send_json({"type": "tcp_data", "stream_id": _sid, "b64": b64e(chunk)})
                                    except Exception:
                                        pass
                                    finally:
                                        await ws.send_json({"type": "tcp_close", "stream_id": _sid, "who": "client"})
                                asyncio.create_task(pump_local_to_ws())

                            elif mtype == "tcp_data":
                                sid = data["stream_id"]; payload = b64d(data.get("b64", ""))
                                io = tcp_streams.get(sid)
                                if io:
                                    reader, writer = io
                                    try:
                                        writer.write(payload)
                                        await writer.drain()
                                    except Exception:
                                        pass

                            elif mtype == "tcp_close":
                                sid = data["stream_id"]
                                io = tcp_streams.pop(sid, None)
                                if io:
                                    _, writer = io
                                    try:
                                        writer.close()
                                    except Exception:
                                        pass

                            elif mtype == "udp_open":
                                # {name, flow_id}
                                name = data["name"]; fid = data["flow_id"]
                                if name not in udp_map:
                                    await ws.send_json({"type": "udp_close", "flow_id": fid, "who": "client"})
                                    continue
                                umap = udp_map[name]
                                loop = asyncio.get_running_loop()
                                # flow마다 별도 소켓 열기 (remote=local_target)
                                async def on_recv_from_local(payload: bytes, _fid=fid):
                                    await ws.send_json({"type": "udp_data", "flow_id": _fid, "b64": b64e(payload)})
                                try:
                                    transport = await open_udp_flow(loop, name, umap.host, umap.port, on_recv_from_local)
                                except Exception:
                                    await ws.send_json({"type": "udp_close", "flow_id": fid, "who": "client"})
                                    continue
                                umap.flows[fid] = UDPFlow(name, transport)

                            elif mtype == "udp_data":
                                fid = data["flow_id"]; payload = b64d(data.get("b64", ""))
                                # 해당 flow로 local target에 전송
                                for umap in udp_map.values():
                                    flow = umap.flows.get(fid)
                                    if flow:
                                        try:
                                            flow.sock.sendto(payload)  # remote_addr 고정 연결
                                        except Exception:
                                            pass
                                        break

                            elif mtype == "udp_close":
                                fid = data["flow_id"]
                                for umap in udp_map.values():
                                    flow = umap.flows.pop(fid, None)
                                    if flow:
                                        try:
                                            flow.sock.close()
                                        except Exception:
                                            pass
                                        break

                        elif msg.type == aiohttp.WSMsgType.CLOSED:
                            break
                        elif msg.type == aiohttp.WSMsgType.ERROR:
                            break
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[WARN] WS error: {e}")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 10.0)
        else:
            await asyncio.sleep(1.0)
            backoff = 1.0

    print("[EXIT] client terminated")

def parse_args():
    if len(sys.argv) < 4:
        usage()
    ws_url = sys.argv[1].strip()
    subdomain = sys.argv[2].strip()
    token = sys.argv[3].strip()

    http_base = None
    tcp_map: Dict[str, TCPMap] = {}
    udp_map: Dict[str, UDPMap] = {}

    i = 4
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--http":
            i += 1
            if i >= len(sys.argv): usage()
            http_base = sys.argv[i]
        elif arg == "--tcp":
            i += 1
            if i >= len(sys.argv) or "=" not in sys.argv[i] or ":" not in sys.argv[i]: usage()
            name, addr = sys.argv[i].split("=", 1)
            host, port = addr.rsplit(":", 1)
            tcp_map[name] = TCPMap(name, host, int(port))
        elif arg == "--udp":
            i += 1
            if i >= len(sys.argv) or "=" not in sys.argv[i] or ":" not in sys.argv[i]: usage()
            name, addr = sys.argv[i].split("=", 1)
            host, port = addr.rsplit(":", 1)
            udp_map[name] = UDPMap(name, host, int(port))
        else:
            usage()
        i += 1

    return ws_url, subdomain, token, http_base, tcp_map, udp_map

async def amain():
    ws_url, subdomain, token, http_base, tcp_map, udp_map = parse_args()
    await run_client(ws_url, subdomain, token, http_base, tcp_map, udp_map)

if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
