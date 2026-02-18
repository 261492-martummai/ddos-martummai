import asyncio
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import DefaultDict, Optional

from fastapi import Cookie, FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from scapy.all import IP, TCP, UDP, sniff

from ddos_martummai.authen import _validate_session
from ddos_martummai.authen import router as auth_router

# ===================== APP SETUP =====================
app = FastAPI()
current_dir = Path(__file__).parent.resolve()

# Auth routes: /auth/login, /auth/logout, /auth/me
app.include_router(auth_router)

current_dir = Path(__file__).parent.resolve()
app.mount("/static", StaticFiles(directory=current_dir / "static"), name="static")


# ===================== ROOT REDIRECT =====================
@app.get("/")
def root():
    """Redirect root to login page."""
    return RedirectResponse(url="/login")


# ===================== HTML ROUTES WITH NO-CACHE =====================
@app.get("/login")
def login_page():
    """Serve login.html with cache-busting headers."""
    return FileResponse(
        current_dir / "static" / "login.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        }
    )


@app.get("/monitor")
def monitor_page():
    """Serve index.html with cache-busting headers."""
    return FileResponse(
        current_dir / "static" / "index.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        }
    )


# ===================== CONFIGURATION =====================
BW_WINDOW   = 60   # seconds of bandwidth history
FLOW_WINDOW = 10   # flows before resetting port counters


# ===================== DATA CLASSES =====================
@dataclass
class FlowStats:
    start:   int = 0
    packets: int = 0
    bytes:   int = 0
    syn:     int = 0
    ack:     int = 0
    psh:     int = 0
    rst:     int = 0
    fin:     int = 0


@dataclass
class TableRow:
    time:     str
    src:      str
    dst:      str
    port:     int
    packets:  int
    bytes:    int
    syn:      int
    ack:      int
    psh:      int
    rst:      int
    fin:      int
    start:    int
    duration: int


# ===================== GLOBAL STATE =====================
bandwidth_tcp:  deque[int]       = deque(maxlen=BW_WINDOW)
bandwidth_udp:  deque[int]       = deque(maxlen=BW_WINDOW)
pkt_rate_tcp:   deque[int]       = deque(maxlen=BW_WINDOW)  # packets/sec TCP
pkt_rate_udp:   deque[int]       = deque(maxlen=BW_WINDOW)  # packets/sec UDP
bw_labels:      deque[str]       = deque(maxlen=BW_WINDOW)
ports_counter:  DefaultDict[int, int] = defaultdict(int)
ports_snapshot: dict[int, int]   = {}
flows:          dict[tuple, FlowStats] = {}
table:          deque[TableRow]  = deque(maxlen=20)
flow_counter:   int              = 0

# Packet counting for rate calculation
_last_second:   int              = int(time.time())
_tcp_count_sec: int              = 0
_udp_count_sec: int              = 0

# Thread lock — capture thread writes, WS handler reads
_lock = threading.Lock()


# ===================== PURE HELPERS =====================
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
    flow.bytes   += size
    if proto == "TCP":
        flow.syn += int("S" in flags)
        flow.ack += int("A" in flags)
        flow.psh += int("P" in flags)
        flow.rst += int("R" in flags)
        flow.fin += int("F" in flags)
    return now - flow.start


def build_table_row(pkt, dport: int, flow: FlowStats, duration: int, ts: str) -> TableRow:
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
    global flow_counter, ports_snapshot, _last_second, _tcp_count_sec, _udp_count_sec

    if IP not in pkt:
        return

    proto, dport, flags = extract_transport(pkt)
    if dport is None:
        return

    size = len(pkt)
    ts   = time.strftime("%H:%M:%S")
    now  = time.time_ns()
    current_sec = int(time.time())

    with _lock:
        # --- packet rate: count packets per second ---
        if current_sec != _last_second:
            # New second started — record last second's counts
            pkt_rate_tcp.append(_tcp_count_sec)
            pkt_rate_udp.append(_udp_count_sec)
            # Reset counters
            _tcp_count_sec = 0
            _udp_count_sec = 0
            _last_second = current_sec
        
        # Increment packet counter
        if proto == "TCP":
            _tcp_count_sec += 1
        elif proto == "UDP":
            _udp_count_sec += 1

        # --- bandwidth: track TCP and UDP separately ---
        if proto == "TCP":
            bandwidth_tcp.append(size)
            bandwidth_udp.append(0)
        elif proto == "UDP":
            bandwidth_tcp.append(0)
            bandwidth_udp.append(size)
        else:
            bandwidth_tcp.append(0)
            bandwidth_udp.append(0)
        
        bw_labels.append(ts)

        # --- ports ---
        ports_counter[dport] += 1
        flow_counter += 1
        if flow_counter >= FLOW_WINDOW:
            ports_snapshot  = dict(ports_counter)
            ports_counter.clear()
            flow_counter = 0
        else:
            ports_snapshot = dict(ports_counter)

        # --- flows ---
        key = (pkt[IP].src, pkt[IP].dst, dport)
        if key not in flows:
            flows[key] = FlowStats(start=now)

        flow     = flows[key]
        duration = update_flow(flow, size, proto, flags, now)
        row      = build_table_row(pkt, dport, flow, duration, ts)
        table.appendleft(row)


# ===================== PACKET CAPTURE THREAD =====================
def capture() -> None:
    sniff(prn=handle, store=0)


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
    try:
        while True:
            with _lock:
                payload = {
                    "bandwidth_tcp": list(bandwidth_tcp),
                    "bandwidth_udp": list(bandwidth_udp),
                    "pkt_rate_tcp":  list(pkt_rate_tcp),
                    "pkt_rate_udp":  list(pkt_rate_udp),
                    "bw_labels":     list(bw_labels),
                    "ports":         ports_snapshot,
                    "table":         [asdict(r) for r in table],
                }
            await websocket.send_json(payload)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass


# ===================== THREAD BOOTSTRAP =====================
def start() -> None:
    threading.Thread(target=capture, daemon=True).start()