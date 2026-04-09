#!/usr/bin/env python3
"""
pacmap - network traffic graph visualizer for kitty terminal
nodes arranged equidistant on a circle, edges + glowing packet dots

requires:
    pip install cairocffi --break-system-packages
    pip install scapy --break-system-packages

run with: sudo python3 pacmap.py [interface]   (default: en0)
"""

import base64
import math
import random
import struct
import curses
import sys
import os
import threading
import time
import zlib
from collections import defaultdict

import cairocffi as cairo
from scapy.all import sniff, IP, TCP, UDP, DNS

lock = threading.Lock()

# ── config ────────────────────────────────────────────────────────────────────
IFACE = sys.argv[1] if len(sys.argv) > 1 else "en0"
FPS = 30
WIDTH = 1200
HEIGHT = 900
CX = WIDTH // 2
CY = HEIGHT // 2
RADIUS = 320  # circle radius for nodes
NODE_R = 8  # node dot radius
DOT_R = 4  # packet dot radius
MIN_REDRAW = 0.04  # max ~25 fps
MAX_DOTS = 500

BG = (0.02, 0.02, 0.06, 1.0)
NODE_COL = (0.0, 0.85, 1.0)
EDGE_COL = (0.2, 0.5, 0.7, 0.5)
LABEL_COL = (0.0, 1.0, 1.0)
GLOW_COL = (0.0, 0.85, 1.0, 0.15)
TITLE_COL = (1.0, 0.0, 1.0)

PROTO_COLS = {
    "TCP": (0.0, 1.0, 1.0),
    "UDP": (1.0, 0.0, 1.0),
    "DNS": (0.0, 1.0, 0.53),
    "OTHER": (1.0, 0.67, 0.0),
}

# ── state ─────────────────────────────────────────────────────────────────────
lock = threading.Lock()
node_order = []  # list of IPs in circle order
node_data = {}  # ip -> {x, y, bytes, packets}
edge_set = set()  # frozenset({ip, ip})
live_dots = []  # {sx,sy,dx,dy,progress,speed,r,g,b}
total_pkts = 0
dirty = threading.Event()
last_draw = 0.0


# ── node position helpers ─────────────────────────────────────────────────────
def recompute_positions():
    """Evenly space all known nodes around the circle."""
    n = len(node_order)
    if n == 0:
        return
    for i, ip in enumerate(node_order):
        angle = (2 * math.pi * i / n) - math.pi / 2
        node_data[ip]["x"] = CX + RADIUS * math.cos(angle)
        node_data[ip]["y"] = CY + RADIUS * math.sin(angle)


def ensure_node(ip):
    if ip not in node_data:
        node_data[ip] = {"x": CX, "y": CY, "bytes": 0, "packets": 0}
        node_order.append(ip)
        recompute_positions()


# ── packet capture ────────────────────────────────────────────────────────────
def get_proto(pkt):
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"


def on_packet(pkt):
    global total_pkts
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)
    proto = get_proto(pkt)
    color = PROTO_COLS.get(proto, PROTO_COLS["OTHER"])

    with lock:
        ensure_node(src)
        ensure_node(dst)
        node_data[src]["bytes"] += size
        node_data[src]["packets"] += 1
        node_data[dst]["bytes"] += size
        node_data[dst]["packets"] += 1
        edge_set.add(frozenset({src, dst}))

        if len(live_dots) < MAX_DOTS:
            s = node_data[src]
            d = node_data[dst]
            live_dots.append(
                {
                    "sx": s["x"],
                    "sy": s["y"],
                    "dx": d["x"],
                    "dy": d["y"],
                    "progress": 0.0,
                    "speed": 0.014 + random.uniform(0, 0.01),
                    "r": color[0],
                    "g": color[1],
                    "b": color[2],
                }
            )

        total_pkts += 1

    dirty.set()


# ── cairo rendering ───────────────────────────────────────────────────────────
def draw_frame(stdscr, nodes_snap, edges_snap, dots_snap, total):
    stdscr.erase()

    height, width = stdscr.getmaxyx()

    # Title
    stdscr.addstr(0, 0, "pacmap (terminal mode)")
    stdscr.addstr(
        1,
        0,
        f"nodes: {len(nodes_snap)}   edges: {len(edges_snap)}   packets: {total}",
    )

    # Draw edges
    for edge in edges_snap:
        ips = list(edge)
        if len(ips) != 2:
            continue

        a = nodes_snap.get(ips[0])
        b = nodes_snap.get(ips[1])

        if not a or not b:
            continue

        x1 = int(a["x"] % width)
        y1 = int(a["y"] % height)
        x2 = int(b["x"] % width)
        y2 = int(b["y"] % height)

        dx = abs(x2 - x1)
        dy = abs(y2 - y1)
        sx = 1 if x1 < x2 else -1
        sy = 1 if y1 < y2 else -1
        err = dx - dy

        while True:
            try:
                stdscr.addstr(y1, x1, "·")
            except:
                pass

            if x1 == x2 and y1 == y2:
                break

            e2 = 2 * err

            if e2 > -dy:
                err -= dy
                x1 += sx

            if e2 < dx:
                err += dx
                y1 += sy

    # Draw nodes
    for ip, nd in nodes_snap.items():
        x = int(nd["x"] % width)
        y = int(nd["y"] % height)

        try:
            stdscr.addstr(y, x, "●")
        except:
            pass

        label_x = min(width - len(ip) - 1, x + 2)
        label_y = min(height - 1, y)

        try:
            stdscr.addstr(label_y, label_x, ip)
        except:
            pass

    # Packet dots
    for dot in dots_snap:
        t = dot["progress"]

        px = int((dot["sx"] + (dot["dx"] - dot["sx"]) * t) % width)
        py = int((dot["sy"] + (dot["dy"] - dot["sy"]) * t) % height)

        try:
            stdscr.addstr(py, px, "*")
        except:
            pass

    stdscr.refresh()


# ── kitty graphics protocol ───────────────────────────────────────────────────
def send_kitty_image(surface):
    """Encode cairo surface as RGBA and push to kitty via APC escape."""
    w = surface.get_width()
    h = surface.get_height()
    data = bytes(surface.get_data())

    # cairo ARGB32 is B G R A in memory on little-endian → convert to RGBA
    import array

    pixels = array.array("B", data)
    for i in range(0, len(pixels), 4):
        b, g, r, a = pixels[i], pixels[i + 1], pixels[i + 2], pixels[i + 3]
        pixels[i], pixels[i + 1] = r, g
        pixels[i + 2], pixels[i + 3] = b, a
    rgba = bytes(pixels)

    compressed = zlib.compress(rgba)
    encoded = base64.standard_b64encode(compressed).decode()

    # first chunk: full metadata
    chunk_size = 4096
    chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]

    def esc(payload, more=0):
        return f"\x1b_Ga=T,f=32,v={h},s={w},m={more},o=z;{payload}\x1b\\"

    # move cursor to top-left, hide it, send image, show cursor
    sys.stdout.write("\x1b[H\x1b[?25l")

    for idx, chunk in enumerate(chunks):
        more = 1 if idx < len(chunks) - 1 else 0
        if idx == 0:
            sys.stdout.write(esc(chunk, more))
        else:
            cont = f"\x1b_Gm={more};{chunk}\x1b\\"
            sys.stdout.write(cont)

    sys.stdout.write("\x1b[?25h")
    sys.stdout.flush()


# ── advance packet dots ───────────────────────────────────────────────────────
def advance_dots():
    """Move dots forward; remove finished ones. Call before snapshot."""
    expired = []
    for i, dot in enumerate(live_dots):
        dot["progress"] += dot["speed"]
        if dot["progress"] >= 1.0:
            expired.append(i)
    for i in reversed(expired):
        live_dots.pop(i)


# ── main render loop ──────────────────────────────────────────────────────────
def render_loop(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)

    while True:
        with lock:
            advance_dots()
            nodes_snap = dict(node_data)
            edges_snap = set(edge_set)
            dots_snap = list(live_dots)
            total = total_pkts

        draw_frame(stdscr, nodes_snap, edges_snap, dots_snap, total)

        time.sleep(1 / FPS)


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    print(f"pacmap starting on {IFACE} — requires sudo", flush=True)
    print("Ctrl+C to quit\n", flush=True)
    time.sleep(0.5)

    sniff_thread = threading.Thread(
        target=lambda: sniff(
            prn=on_packet,
            store=False,
            filter="ip",
            iface=IFACE,
            promisc=False,
        ),
        daemon=True,
    )

    sniff_thread.start()

    curses.wrapper(render_loop)


if __name__ == "__main__":
    main()
