import asyncio
import queue
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import DefaultDict, Optional

from fastapi import Cookie, FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from scapy.all import IP, TCP, UDP, sniff  # type: ignore

from ddos_martummai.init_models import FlowStats, TableRow
from ddos_martummai.web.authen import _validate_session
from ddos_martummai.web.drift_monitor import (
    check_auto_baseline,
    drift_score,
    update_drift_rate,
)
from ddos_martummai.web.router import router

# ==========================================
# CONFIGURATION & GLOBAL STATE
# ==========================================
BW_WINDOW = 60  # seconds of bandwidth history
FLOW_WINDOW = 10  # flows before resetting port counters

_lock = threading.Lock()

# ===================== GLOBAL STATE =====================
bandwidth_tcp: deque[int] = deque(maxlen=BW_WINDOW)
bandwidth_udp: deque[int] = deque(maxlen=BW_WINDOW)
pkt_rate_tcp: deque[int] = deque(maxlen=BW_WINDOW)  # packets/sec TCP
pkt_rate_udp: deque[int] = deque(maxlen=BW_WINDOW)  # packets/sec UDP
bw_labels: deque[str] = deque(maxlen=BW_WINDOW)

ports_counter: DefaultDict[int, int] = defaultdict(int)
ports_snapshot: dict[int, int] = {}
flows: dict[tuple, FlowStats] = {}
table: deque[TableRow] = deque(maxlen=20)
flow_counter: int = 0

mitigation_event_queue = None
active_connections: set[WebSocket] = set()

# Packet counting for rate calculation
_last_second: int = int(time.time())
_tcp_count_sec: int = 0
_udp_count_sec: int = 0
_tcp_bytes_sec: int = 0
_udp_bytes_sec: int = 0
_last_timestamp: str = ""


# ==========================================
# CORE LOGIC / HELPER FUNCTIONS
# ==========================================
def extract_transport(pkt) -> tuple[str | None, int | None, str]:
    """Return (proto, dport, flags) from a scapy packet."""
    if TCP in pkt:
        return "TCP", pkt[TCP].dport, str(pkt[TCP].flags)
    if UDP in pkt:
        return "UDP", pkt[UDP].dport, ""
    return None, None, ""


def update_flow(flow: FlowStats, size: int, proto: str, flags: str, now: int) -> int:
    """Mutate flow in-place and return duration."""
    flow.packets += 1
    flow.bytes += size
    if proto == "TCP":
        flow.syn += int("S" in flags)
        flow.ack += int("A" in flags)
        flow.psh += int("P" in flags)
        flow.rst += int("R" in flags)
        flow.fin += int("F" in flags)
    return now - flow.start


def build_table_row(
    pkt, dport: int, flow: FlowStats, duration: int, ts: str
) -> TableRow:
    return TableRow(
        time=ts,
        src=pkt[IP].src,
        dst=pkt[IP].dst,
        port=dport,
        packets=flow.packets,
        bytes=flow.bytes,
        syn=flow.syn,
        ack=flow.ack,
        psh=flow.psh,
        rst=flow.rst,
        fin=flow.fin,
        start=flow.start,
        duration=duration,
    )


# ===================== PACKET HANDLER =====================
def handle(pkt) -> None:
    global \
        flow_counter, \
        ports_snapshot, \
        _last_second, \
        _tcp_count_sec, \
        _udp_count_sec, \
        _tcp_bytes_sec, \
        _udp_bytes_sec, \
        _last_timestamp

    if IP not in pkt:
        return

    proto, dport, flags = extract_transport(pkt)
    if dport is None or proto is None:
        return

    size = len(pkt)
    ts = time.strftime("%H:%M:%S")
    now = time.time_ns()
    current_sec = int(time.time())

    with _lock:
        # --- packet rate & bandwidth: count packets per second ---
        if current_sec != _last_second:
            # New second started — record last second's counts
            pkt_rate_tcp.append(_tcp_count_sec)
            pkt_rate_udp.append(_udp_count_sec)
            bandwidth_tcp.append(_tcp_bytes_sec)
            bandwidth_udp.append(_udp_bytes_sec)
            bw_labels.append(_last_timestamp or ts)

            # Update drift monitor
            total_pkt = _tcp_count_sec + _udp_count_sec
            total_bytes = sum(bandwidth_tcp) + sum(bandwidth_udp)
            update_drift_rate(total_pkt, total_bytes)

            # Reset counters
            _tcp_count_sec = 0
            _udp_count_sec = 0
            _tcp_bytes_sec = 0
            _udp_bytes_sec = 0
            _last_second = current_sec

        # Store current timestamp
        _last_timestamp = ts
        # Increment packet counter
        if proto == "TCP":
            _tcp_count_sec += 1
            _tcp_bytes_sec += size
        elif proto == "UDP":
            _udp_count_sec += 1
            _udp_bytes_sec += size

        # --- ports ---
        ports_counter[dport] += 1
        flow_counter += 1
        if flow_counter >= FLOW_WINDOW:
            ports_snapshot = dict(ports_counter)
            ports_counter.clear()
            flow_counter = 0
        else:
            ports_snapshot = dict(ports_counter)

        # --- flows ---
        key = (pkt[IP].src, pkt[IP].dst, dport)
        if key not in flows:
            flows[key] = FlowStats(start=now)

        flow = flows[key]
        duration = update_flow(flow, size, proto, flags, now)
        row = build_table_row(pkt, dport, flow, duration, ts)
        table.appendleft(row)


# ===================== PACKET CAPTURE THREAD =====================
def capture() -> None:
    sniff(prn=handle, store=0)


# ===================== THREAD BOOTSTRAP =====================
def start() -> None:
    threading.Thread(target=capture, daemon=True).start()


def set_mitigation_queue(queue) -> None:
    global mitigation_event_queue
    mitigation_event_queue = queue


# ==========================================
# BACKGROUND TASKS
# ==========================================
async def broadcast_mitigations_bg():
    while True:
        if mitigation_event_queue is not None:
            try:
                alert = mitigation_event_queue.get_nowait()
                payload = {"type": "alert", "data": alert}

                disconnected = set()
                for ws in active_connections:
                    try:
                        await ws.send_json(payload)
                    except WebSocketDisconnect:
                        disconnected.add(ws)

                for ws in disconnected:
                    active_connections.discard(ws)

            except queue.Empty:
                pass
        await asyncio.sleep(0.3)


# ==========================================
# FASTAPI APP INIT & LIFESPAN
# ==========================================
@asynccontextmanager
async def app_lifespan(app: FastAPI):
    bg_task = asyncio.create_task(broadcast_mitigations_bg())
    yield
    bg_task.cancel()


app = FastAPI(lifespan=app_lifespan)

current_dir = Path(__file__).parent.resolve()
app.mount("/static", StaticFiles(directory=current_dir / "static"), name="static")
app.include_router(router)


# ===================== WEBSOCKET API =====================
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    nm_session: Optional[str] = Cookie(default=None),
) -> None:
    # Reject unauthenticated WebSocket connections before accepting
    if not _validate_session(nm_session):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    active_connections.add(websocket)

    try:
        while True:
            with _lock:
                current_drift = drift_score()

                check_auto_baseline(current_drift)

                payload = {
                    "type": "telemetry",
                    "data": {
                        "bandwidth_tcp": list(bandwidth_tcp),
                        "bandwidth_udp": list(bandwidth_udp),
                        "pkt_rate_tcp": list(pkt_rate_tcp),
                        "pkt_rate_udp": list(pkt_rate_udp),
                        "bw_labels": list(bw_labels),
                        "ports": ports_snapshot,
                        "table": [asdict(r) for r in table],
                        "drift": current_drift,
                    },
                }
            await websocket.send_json(payload)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        active_connections.discard(websocket)
