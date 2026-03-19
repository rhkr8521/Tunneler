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
import contextlib
import json
import os
import signal
import sys
from typing import Dict, Optional, Tuple

import aiohttp

APP_NAME = "tunneler-client"

def app_version(default: str = "dev") -> str:
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


def usage():
    print("Usage: client.py WS_URL SUBDOMAIN TOKEN [--http URL] [--tcp name=host:port]* [--udp name=host:port]*")
    sys.exit(1)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


class TCPMap:
    def __init__(self, name: str, host: str, port: int):
        self.name = name
        self.host = host
        self.port = port


class UDPFlow:
    def __init__(self, name: str, sock: asyncio.DatagramTransport):
        self.name = name
        self.sock = sock


class UDPMap:
    def __init__(self, name: str, host: str, port: int):
        self.name = name
        self.host = host
        self.port = port
        self.flows: Dict[str, UDPFlow] = {}


async def open_udp_flow(loop: asyncio.AbstractEventLoop, target_host: str, target_port: int, on_recv):
    class CliUDP(asyncio.DatagramProtocol):
        def connection_made(self, transport: asyncio.DatagramTransport):
            self.transport = transport

        def datagram_received(self, data: bytes, addr):
            asyncio.create_task(on_recv(data))

        def error_received(self, exc):
            pass

    transport, _ = await loop.create_datagram_endpoint(
        lambda: CliUDP(),
        remote_addr=(target_host, target_port),
    )
    return transport


def normalize_mapping_payload(raw: dict) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    name = (raw.get("name") or "").strip()
    host = (raw.get("host") or "").strip()
    port = int(raw.get("port") or 0)
    remote_port = int(raw.get("remote_port") or 0)
    if not name or not host or port <= 0 or port > 65535:
        return None
    return {"name": name, "host": host, "port": port, "remote_port": remote_port}


async def cleanup_runtime(
    tcp_streams: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]],
    udp_groups: Tuple[Dict[str, UDPMap], ...],
):
    for _, writer in list(tcp_streams.values()):
        with contextlib.suppress(Exception):
            writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    tcp_streams.clear()

    for udp_map in udp_groups:
        for mapping in udp_map.values():
            for flow in list(mapping.flows.values()):
                with contextlib.suppress(Exception):
                    flow.sock.close()
            mapping.flows.clear()


async def run_client(
    ws_url: str,
    subdomain: str,
    token: str,
    http_base: Optional[str],
    tcp_map: Dict[str, TCPMap],
    udp_map: Dict[str, UDPMap],
):
    backoff = 1.0
    stop_event = asyncio.Event()
    hold_mode = False
    restart_requested = False

    def handle_sig():
        stop_event.set()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, handle_sig)
        loop.add_signal_handler(signal.SIGTERM, handle_sig)
    except NotImplementedError:
        pass

    while not stop_event.is_set():
        if hold_mode:
            print("[INFO] 연결이 관리자에 의해 중단되었습니다. 프로세스 재시작 전까지 대기합니다.")
            await stop_event.wait()
            break

        managed_tcp_map: Dict[str, TCPMap] = {}
        managed_udp_map: Dict[str, UDPMap] = {}
        disabled_tcp_names = set()
        disabled_udp_names = set()
        tcp_streams: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        error: Optional[Exception] = None

        try:
            timeout = aiohttp.ClientTimeout(total=None, sock_read=None, sock_connect=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(ws_url, heartbeat=20) as ws:
                    print(f"[INFO] WS connected to {ws_url}")
                    await ws.send_json({
                        "type": "register",
                        "subdomain": subdomain,
                        "auth_token": token,
                        "tcp_configs": [{"name": m.name, "remote_port": 0} for m in tcp_map.values()],
                        "udp_configs": [{"name": m.name, "remote_port": 0} for m in udp_map.values()],
                    })

                    assigned_once = False

                    def resolve_tcp(name: str) -> Optional[TCPMap]:
                        if name in disabled_tcp_names:
                            return None
                        return tcp_map.get(name) or managed_tcp_map.get(name)

                    def resolve_udp(name: str) -> Optional[UDPMap]:
                        if name in disabled_udp_names:
                            return None
                        return udp_map.get(name) or managed_udp_map.get(name)

                    def close_udp_mapping(name: str):
                        mapping = managed_udp_map.get(name) or udp_map.get(name)
                        if not mapping:
                            return
                        for flow in list(mapping.flows.values()):
                            with contextlib.suppress(Exception):
                                flow.sock.close()
                        mapping.flows.clear()

                    def sync_managed_maps(proto: str, raw_items):
                        target = managed_tcp_map if proto == "tcp" else managed_udp_map
                        base = tcp_map if proto == "tcp" else udp_map
                        target.clear()
                        for raw in raw_items or []:
                            cfg = normalize_mapping_payload(raw)
                            if not cfg or cfg["name"] in base:
                                continue
                            if proto == "tcp":
                                target[cfg["name"]] = TCPMap(cfg["name"], cfg["host"], cfg["port"])
                            else:
                                target[cfg["name"]] = UDPMap(cfg["name"], cfg["host"], cfg["port"])

                    async def send_ack(req_id: str, ok: bool, reason: str = ""):
                        if not req_id or ws.closed:
                            return
                        try:
                            await ws.send_json({"type": "control_ack", "id": req_id, "ok": ok, "reason": reason})
                        except Exception:
                            pass

                    async def do_proxy(req: dict) -> dict:
                        if not http_base:
                            return {"status": 502, "headers": [], "body_b64": b64e(b"HTTP base not configured")}
                        method = req.get("method", "GET")
                        path_qs = req.get("path_qs", "/")
                        headers = req.get("headers", [])
                        body = b64d(req.get("body_b64", ""))

                        if http_base.endswith("/") and path_qs.startswith("/"):
                            url = http_base[:-1] + path_qs
                        else:
                            url = http_base + path_qs

                        hdict = {}
                        for key, value in headers:
                            if key.lower() in ("host", "content-length", "connection", "upgrade"):
                                continue
                            hdict[key] = value

                        try:
                            async with aiohttp.ClientSession() as proxy_session:
                                async with proxy_session.request(method, url, headers=hdict, data=body) as resp:
                                    payload = await resp.read()
                                    return {
                                        "status": resp.status,
                                        "headers": [(k, v) for k, v in resp.headers.items()],
                                        "body_b64": b64e(payload),
                                    }
                        except Exception as exc:
                            return {"status": 502, "headers": [], "body_b64": b64e(str(exc).encode())}

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = json.loads(msg.data)
                            except Exception:
                                continue

                            mtype = data.get("type")

                            if mtype == "register_result":
                                if data.get("ok"):
                                    sync_managed_maps("tcp", data.get("managed_tcp_configs"))
                                    sync_managed_maps("udp", data.get("managed_udp_configs"))
                                    tcp_assigned = data.get("tcp_assigned", [])
                                    udp_assigned = data.get("udp_assigned", [])
                                    print("[OK] 등록 성공. 원격 포트 할당:")
                                    if tcp_assigned:
                                        print("  TCP:", ", ".join(f"{e['name']}={e['remote_port']}" for e in tcp_assigned))
                                    if udp_assigned:
                                        print("  UDP:", ", ".join(f"{e['name']}={e['remote_port']}" for e in udp_assigned))
                                    if managed_tcp_map or managed_udp_map:
                                        print("[INFO] 서버에서 관리 중인 런타임 매핑을 동기화했습니다.")
                                    if not assigned_once:
                                        assigned_once = True
                                        print("관리자 대시보드에서 현재 할당 포트를 확인하세요.")
                                else:
                                    print(f"[ERR] register failed: {data.get('reason')}")
                                    await asyncio.sleep(3)
                                    break

                            elif mtype == "control":
                                req_id = data.get("id", "")
                                action = (data.get("action") or "").strip().lower()

                                if action == "disconnect":
                                    await send_ack(req_id, True)
                                    hold_mode = True
                                    await ws.close(message=b"server_disconnect")
                                    break

                                if action == "restart":
                                    await send_ack(req_id, True)
                                    restart_requested = True
                                    await ws.close(message=b"server_restart")
                                    break

                                if action == "add_mapping":
                                    proto = (data.get("proto") or "").strip().lower()
                                    cfg = normalize_mapping_payload(data.get("mapping") or {})
                                    if not cfg or proto not in ("tcp", "udp"):
                                        await send_ack(req_id, False, "bad_mapping")
                                        continue
                                    if proto == "tcp":
                                        if cfg["name"] in tcp_map:
                                            await send_ack(req_id, False, "name_used_by_static")
                                            continue
                                        if cfg["name"] in managed_tcp_map:
                                            await send_ack(req_id, False, "duplicate_name")
                                            continue
                                        managed_tcp_map[cfg["name"]] = TCPMap(cfg["name"], cfg["host"], cfg["port"])
                                    else:
                                        if cfg["name"] in udp_map:
                                            await send_ack(req_id, False, "name_used_by_static")
                                            continue
                                        if cfg["name"] in managed_udp_map:
                                            await send_ack(req_id, False, "duplicate_name")
                                            continue
                                        managed_udp_map[cfg["name"]] = UDPMap(cfg["name"], cfg["host"], cfg["port"])
                                    await send_ack(req_id, True)
                                    print(f"[INFO] 런타임 {proto.upper()} 매핑 추가: {cfg['name']} -> {cfg['host']}:{cfg['port']}")
                                    continue

                                if action == "remove_mapping":
                                    proto = (data.get("proto") or "").strip().lower()
                                    name = (data.get("name") or "").strip()
                                    if proto not in ("tcp", "udp") or not name:
                                        await send_ack(req_id, False, "bad_mapping")
                                        continue
                                    if proto == "tcp":
                                        if name in managed_tcp_map:
                                            managed_tcp_map.pop(name, None)
                                        if name in tcp_map:
                                            disabled_tcp_names.add(name)
                                    else:
                                        if name in managed_udp_map:
                                            mapping = managed_udp_map.pop(name, None)
                                            if mapping:
                                                for flow in list(mapping.flows.values()):
                                                    with contextlib.suppress(Exception):
                                                        flow.sock.close()
                                                mapping.flows.clear()
                                        if name in udp_map:
                                            disabled_udp_names.add(name)
                                            close_udp_mapping(name)
                                    await send_ack(req_id, True)
                                    print(f"[INFO] 런타임 {proto.upper()} 매핑 제거: {name}")
                                    continue

                                await send_ack(req_id, False, "unsupported_action")

                            elif mtype == "proxy_request":
                                rid = data.get("id")
                                req = data.get("request", {})
                                resp = await do_proxy(req)
                                await ws.send_json({"type": "proxy_response", "id": rid, **resp})

                            elif mtype == "tcp_open":
                                name = data["name"]
                                sid = data["stream_id"]
                                target = resolve_tcp(name)
                                if not target:
                                    await ws.send_json({"type": "tcp_close", "stream_id": sid, "who": "client"})
                                    continue
                                try:
                                    reader, writer = await asyncio.open_connection(target.host, target.port)
                                except Exception:
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
                                        with contextlib.suppress(Exception):
                                            await ws.send_json({"type": "tcp_close", "stream_id": _sid, "who": "client"})

                                asyncio.create_task(pump_local_to_ws())

                            elif mtype == "tcp_data":
                                sid = data["stream_id"]
                                payload = b64d(data.get("b64", ""))
                                io = tcp_streams.get(sid)
                                if io:
                                    _, writer = io
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
                                    with contextlib.suppress(Exception):
                                        writer.close()
                                    with contextlib.suppress(Exception):
                                        await writer.wait_closed()

                            elif mtype == "udp_open":
                                name = data["name"]
                                fid = data["flow_id"]
                                mapping = resolve_udp(name)
                                if not mapping:
                                    await ws.send_json({"type": "udp_close", "flow_id": fid, "who": "client"})
                                    continue
                                loop = asyncio.get_running_loop()

                                async def on_recv_from_local(payload: bytes, _fid=fid):
                                    await ws.send_json({"type": "udp_data", "flow_id": _fid, "b64": b64e(payload)})

                                try:
                                    transport = await open_udp_flow(loop, mapping.host, mapping.port, on_recv_from_local)
                                except Exception:
                                    await ws.send_json({"type": "udp_close", "flow_id": fid, "who": "client"})
                                    continue
                                mapping.flows[fid] = UDPFlow(name, transport)

                            elif mtype == "udp_data":
                                fid = data["flow_id"]
                                payload = b64d(data.get("b64", ""))
                                for mapping in list(udp_map.values()) + list(managed_udp_map.values()):
                                    flow = mapping.flows.get(fid)
                                    if flow:
                                        with contextlib.suppress(Exception):
                                            flow.sock.sendto(payload)
                                        break

                            elif mtype == "udp_close":
                                fid = data["flow_id"]
                                for mapping in list(udp_map.values()) + list(managed_udp_map.values()):
                                    flow = mapping.flows.pop(fid, None)
                                    if flow:
                                        with contextlib.suppress(Exception):
                                            flow.sock.close()
                                        break

                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            break

        except asyncio.CancelledError:
            break
        except Exception as exc:
            error = exc
        finally:
            await cleanup_runtime(tcp_streams, (udp_map, managed_udp_map))

        if restart_requested or stop_event.is_set():
            break
        if hold_mode:
            continue
        if error is not None:
            print(f"[WARN] WS error: {error}")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 10.0)
        else:
            await asyncio.sleep(1.0)
            backoff = 1.0

    if restart_requested and not stop_event.is_set():
        print("[INFO] restarting client process")
        os.execv(sys.executable, [sys.executable, *sys.argv])

    print("[EXIT] client terminated")


def parse_args():
    if len(sys.argv) >= 2 and sys.argv[1] in ("-v", "--version"):
        print(f"{APP_NAME} {APP_VERSION}")
        sys.exit(0)
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
            if i >= len(sys.argv):
                usage()
            http_base = sys.argv[i]
        elif arg == "--tcp":
            i += 1
            if i >= len(sys.argv) or "=" not in sys.argv[i] or ":" not in sys.argv[i]:
                usage()
            name, addr = sys.argv[i].split("=", 1)
            host, port = addr.rsplit(":", 1)
            tcp_map[name] = TCPMap(name, host, int(port))
        elif arg == "--udp":
            i += 1
            if i >= len(sys.argv) or "=" not in sys.argv[i] or ":" not in sys.argv[i]:
                usage()
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
