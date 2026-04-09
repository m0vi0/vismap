import argparse
import asyncio
import json
import os
import subprocess
import threading
import time
from collections import defaultdict
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import websockets
from scapy.all import DNS, IP, TCP, UDP, sniff

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "client" / "dist"

clients = set()
node_data = defaultdict(lambda: {"bytes": 0, "packets": 0, "ip": ""})
lock = threading.Lock()
loop = None
capture_thread = None
capture_started = False
capture_error = None
iface = os.environ.get("VISMAP_IFACE", "en0")


def get_protocol(packet):
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    return "OTHER"


async def broadcast(message):
    if not clients:
        return

    dead = set()
    for client in clients:
        try:
            await client.send(message)
        except Exception:
            dead.add(client)
    clients.difference_update(dead)


def broadcast_from_thread(payload):
    if loop and not loop.is_closed():
        asyncio.run_coroutine_threadsafe(broadcast(json.dumps(payload)), loop)


def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    size = len(packet)
    proto = get_protocol(packet)

    with lock:
        node_data[src]["bytes"] += size
        node_data[src]["packets"] += 1
        node_data[src]["ip"] = src
        node_data[dst]["bytes"] += size
        node_data[dst]["packets"] += 1
        node_data[dst]["ip"] = dst

    broadcast_from_thread(
        {
            "type": "packet",
            "src": src,
            "dst": dst,
            "size": size,
            "proto": proto,
            "timestamp": time.time(),
        }
    )


def start_sniff():
    global capture_error

    print(f"Starting packet capture on {iface}...")
    try:
        sniff(prn=packet_callback, store=False, filter="ip", iface=iface, promisc=False)
    except Exception as exc:
        capture_error = str(exc)
        print("Sniff failed:", capture_error)
        broadcast_from_thread(
            {
                "type": "capture_status",
                "status": "error",
                "message": capture_error,
                "iface": iface,
            }
        )


async def start_capture_once(websocket):
    global capture_started, capture_thread

    if capture_error:
        await websocket.send(
            json.dumps(
                {
                    "type": "capture_status",
                    "status": "error",
                    "message": capture_error,
                    "iface": iface,
                }
            )
        )
        return

    if capture_started:
        await websocket.send(
            json.dumps({"type": "capture_status", "status": "running", "iface": iface})
        )
        return

    capture_started = True
    capture_thread = threading.Thread(target=start_sniff, daemon=True)
    capture_thread.start()
    await broadcast(
        json.dumps({"type": "capture_status", "status": "running", "iface": iface})
    )


async def send_nodes():
    while True:
        await asyncio.sleep(3)
        with lock:
            nodes = [
                {"ip": value["ip"], "bytes": value["bytes"], "packets": value["packets"]}
                for value in node_data.values()
                if value["ip"]
            ]
        await broadcast(json.dumps({"type": "nodes", "nodes": nodes}))


async def handler(websocket):
    clients.add(websocket)
    print(f"[+] Client connected. Total: {len(clients)}")

    status = "running" if capture_started else "ready"
    if capture_error:
        status = "error"
    await websocket.send(
        json.dumps(
            {
                "type": "capture_status",
                "status": status,
                "message": capture_error,
                "iface": iface,
            }
        )
    )

    try:
        async for raw_message in websocket:
            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError:
                continue

            if message.get("type") == "start_capture":
                await start_capture_once(websocket)
    finally:
        clients.discard(websocket)
        print(f"[-] Client disconnected. Total: {len(clients)}")


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIST_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        if not DIST_DIR.exists():
            self.send_response(503)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"client/dist is missing. Run: cd client && npm install && npm run build\n"
            )
            return

        requested = DIST_DIR / self.path.lstrip("/")
        if self.path == "/" or not requested.exists():
            self.path = "/index.html"
        super().do_GET()


def start_http_server(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), AppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


async def main():
    global loop
    loop = asyncio.get_running_loop()

    print(f"Starting vismap websocket on ws://127.0.0.1:8765 | iface: {iface}")
    async with websockets.serve(handler, "127.0.0.1", 8765):
        asyncio.create_task(send_nodes())
        await asyncio.Future()


def parse_args():
    parser = argparse.ArgumentParser(description="VISMAP local packet visualizer")
    parser.add_argument("--iface", default=iface, help="Network interface to capture")
    parser.add_argument("--port", type=int, default=8080, help="Frontend HTTP port")
    parser.add_argument("--no-open", action="store_true", help="Do not open the browser")
    return parser.parse_args()


def open_browser(url):
    try:
        if os.uname().sysname == "Darwin":
            subprocess.Popen(["open", url])
        else:
            subprocess.Popen(["python3", "-m", "webbrowser", url])
    except Exception as exc:
        print(f"Could not open browser automatically: {exc}")
        print(f"Open {url} manually.")


if __name__ == "__main__":
    args = parse_args()
    iface = args.iface

    start_http_server(args.port)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Serving vismap app on {url}")
    print("Open the app, then click Start host capture in the browser.")
    print("Packet capture may require launching this process with sudo/admin privileges.")

    if not args.no_open:
        open_browser(url)

    asyncio.run(main())
