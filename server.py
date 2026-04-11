import argparse
import asyncio
import json
import os
import threading
import time
import webbrowser
from collections import defaultdict

import websockets
from scapy.all import DNS, Ether, IP, TCP, UDP, sniff

clients = set()
node_data = defaultdict(lambda: {"bytes": 0, "packets": 0, "ip": ""})
lock = threading.Lock()
loop = None
capture_thread = None
capture_started = False
capture_error = None
iface = os.environ.get("PACMAP_IFACE") or None


def iface_label():
    return iface or "default interface"


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
    src_mac = packet[Ether].src if packet.haslayer(Ether) else None
    dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None
    src_port = None
    dst_port = None
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

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
            "srcIp": src,
            "dstIp": dst,
            "srcMac": src_mac,
            "dstMac": dst_mac,
            "srcPort": src_port,
            "dstPort": dst_port,
        }
    )


def start_sniff():
    global capture_error

    print(f"Starting packet capture on {iface_label()}...")
    try:
        sniff_kwargs = {"prn": packet_callback, "store": False, "filter": "ip", "promisc": False}
        if iface:
            sniff_kwargs["iface"] = iface
        sniff(**sniff_kwargs)
    except Exception as exc:
        capture_error = str(exc)
        print("Sniff failed:", capture_error)
        broadcast_from_thread(
            {
                "type": "capture_status",
                "status": "error",
                "message": capture_error,
                "iface": iface_label(),
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
                    "iface": iface_label(),
                }
            )
        )
        return

    if capture_started:
        await websocket.send(
            json.dumps({"type": "capture_status", "status": "running", "iface": iface_label()})
        )
        return

    capture_started = True
    capture_thread = threading.Thread(target=start_sniff, daemon=True)
    capture_thread.start()
    await broadcast(
        json.dumps({"type": "capture_status", "status": "running", "iface": iface_label()})
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
                "iface": iface_label(),
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


async def main():
    global loop
    loop = asyncio.get_running_loop()

    print(f"Starting pacmap websocket on ws://127.0.0.1:8765 | iface: {iface_label()}")
    async with websockets.serve(handler, "127.0.0.1", 8765):
        asyncio.create_task(send_nodes())
        await asyncio.Future()


def parse_args():
    parser = argparse.ArgumentParser(description="pacmap local packet visualizer")
    parser.add_argument("--iface", default=iface, help="Network interface to capture")
    parser.add_argument("--app-url", default="http://127.0.0.1:5173", help="Frontend app URL")
    parser.add_argument("--open", action="store_true", help="Open the browser automatically")
    parser.add_argument("--no-open", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def open_browser(url):
    try:
        webbrowser.open(url)
    except Exception as exc:
        print(f"Could not open browser automatically: {exc}")
        print(f"Open {url} manually.")


if __name__ == "__main__":
    args = parse_args()
    iface = args.iface

    print(f"Open {args.app_url}, then click Start host capture in the browser.")
    print("Packet capture may require launching this process with sudo/admin privileges.")

    if args.open and not args.no_open:
        open_browser(args.app_url)

    asyncio.run(main())
