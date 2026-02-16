import asyncio
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from scapy.all import IP, TCP, UDP, sniff

app = FastAPI()

current_dir = Path(__file__).parent.resolve()
app.mount("/static", StaticFiles(directory=current_dir / "static"), name="static")
bandwidth = deque(maxlen=60)
ports = defaultdict(int)
flows = {}  # key = (src, dst, dport)
table = deque(maxlen=20)


def capture():
    def handle(pkt):
        if IP in pkt:
            size = len(pkt)
            bandwidth.append(size)

            proto = None
            dport = None
            flags = {}

            if TCP in pkt:
                proto = "TCP"
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
            elif UDP in pkt:
                proto = "UDP"
                dport = pkt[UDP].dport
## dont know
            if not dport:
                return

            ports[dport] += 1
##
            key = (pkt[IP].src, pkt[IP].dst, dport)

            now = time.time_ns()

            if key not in flows:
                flows[key] = {
                    "start": now,
                    "packets": 0,
                    "bytes": 0,
                    "syn": 0,
                    "ack": 0,
                    "psh": 0,
                    "rst": 0,
                    "fin": 0,
                }

            f = flows[key]
            f["packets"] += 1
            f["bytes"] += size

            if proto == "TCP":
                f["syn"] += int("S" in flags)
                f["ack"] += int("A" in flags)
                f["psh"] += int("P" in flags)
                f["rst"] += int("R" in flags)
                f["fin"] += int("F" in flags)

            duration = now - f["start"]

            table.appendleft({
                "time": time.strftime("%H:%M:%S"),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "port": dport,
                "packets": f["packets"],
                "bytes": f["bytes"],
                "syn": f["syn"],
                "ack": f["ack"],
                "psh": f["psh"],
                "rst": f["rst"],
                "fin": f["fin"],
                "start": f["start"],
                "duration": duration
            })

    sniff(prn=handle, store=0)


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    while True:
        await websocket.send_json({
            "bandwidth": list(bandwidth),
            "ports": dict(ports),
            "table": list(table)
        })
        await asyncio.sleep(1)

def start():
    threading.Thread(target=capture, daemon=True).start()
