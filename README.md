# pacmap

PacMap is a graph-first network traffic visualizer for live capture and PCAP replay that helps you see what changed, what's noisy, and what to inspect next.

Think of it as Git for network behavior: snapshot, diff, and replay network state visually.

![pacmap demo](OUTPUT.gif)

## Input Modes

PacMap supports two workflows:

- **Live Capture** — inspect what is happening right now on a local interface.
- **Replay PCAP** — upload a saved `.pcap` or `.pcapng` file and replay packet flow over time.

## Install

From the repo root:

```bash
python3 -m venv venv
source venv/bin/activate
pip install websockets scapy
npm install --prefix client
```

On Windows, create and activate a venv using your normal Python workflow, then install the same packages. Packet capture on Windows requires Npcap.

## Live Capture

Start PacMap from the repo root:

```bash
npm start -- --iface en0
```

Common interface examples:

- macOS Wi-Fi: `en0`
- Linux Ethernet: `eth0`
- Linux Wi-Fi: `wlan0`
- Windows Wi-Fi/Ethernet: use the Npcap interface name shown by Scapy

Open:

```text
http://127.0.0.1:5176
```

Then use the control dock to start live capture.

Raw packet capture usually needs elevated local privileges. On macOS/Linux:

```bash
sudo npm start -- --iface en0
```

On Windows, run the terminal as Administrator.

## Replay PCAP

Open the web app, switch the source to PCAP Replay, and upload a `.pcap` or `.pcapng` file. Then use:

- play / pause / restart
- speed control
- timeline scrubber
- label mode controls for raw/resolved IP and MAC labels

Replay runs in the browser and does not require the Python capture server to be running.

Replay includes investigation panels for conversations, endpoints, protocol breakdown, name resolution, and I/O timeline activity.

File limits: 100 MB and 100,000 packets. Unsupported frames are skipped and counted in the UI.

Current replay support:

- classic `.pcap` and basic `.pcapng`
- common Ethernet, raw IP, Linux cooked, and loopback captures
- IPv4 and IPv6 packets
- TCP, UDP, DNS, and other IP packets

## Display Filter

Both Live Capture and Replay support a Wireshark-style display filter bar. Type a filter and press Enter to apply; clear the field and press Enter to remove it.

Supported syntax:

```
tcp          udp          dns          http         arp
ip.addr == 192.168.1.10
ip.src == 10.0.0.1
ip.dst == 8.8.8.8
tcp.port == 443
udp.port == 53
port == 80
ip.src == 10.0.0.1 && ip.dst == 8.8.8.8
```

Compound filters (`&&`) combine two field filters. Applying a filter narrows the graph to matching nodes and edges; clearing it restores the full view for the current capture window.

## Path Tracing

A compound `ip.src == X && ip.dst == Y` filter activates path tracing. PacMap runs BFS over the full capture to find the hop chain between the two endpoints. A panel appears below the control dock showing each hop with per-edge packet and byte counts, and intermediate nodes are highlighted in the graph.

## Checkpoints

Checkpoints snapshot the current network state — nodes, edges, traffic volumes — at a point in time.

- **Manual checkpoint**: click Checkpoint in the filter bar to save the current state with a custom label.
- **Auto-checkpoint**: the app can automatically checkpoint on new host discovery or external connection events (configurable in the control dock).
- **Diff**: select two checkpoints in the history panel to compare them; added, removed, and changed nodes and edges are highlighted in the graph and listed in the diff panel.
- **Window compare**: use the timeline scrubber to select a time range and compare it against a saved checkpoint baseline.

Checkpoints persist in `localStorage` under `pacmap_checkpoints` (up to 50 entries).

## Why A Local Helper?

Browsers cannot sniff host network traffic or start privileged packet capture directly. PacMap uses a local Python WebSocket helper with Scapy for live capture, then streams packet summaries to the React app at:

```text
ws://127.0.0.1:8765
```

PCAP replay is different: the browser reads the uploaded file and reuses the same graph visualization without needing live packet access.

## Development

Frontend only:

```bash
cd client
npm install
npm run dev
```

Production build:

```bash
npm run build
```

Capture server only:

```bash
source venv/bin/activate
python3 server.py --iface en0
```

## Troubleshooting

- If the UI says the capture server is offline, `server.py` is not running or the WebSocket port is unavailable.
- If capture fails, check the interface name and run with the required local privileges.
- If no live nodes appear, generate traffic with normal browsing, `ping 8.8.8.8`, DNS lookups, or other network activity.
- If a PCAP loads with many skipped packets, it may use an unsupported link type, encrypted/non-IP traffic, or packet types PacMap does not yet summarize.

## Tech

- React + Vite
- Three.js
- Python WebSocket server
- Scapy packet capture
