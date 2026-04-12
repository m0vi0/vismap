# pacmap

PacMap is a local packet visualizer for live traffic mapping and PCAP replay.

It shows hosts as nodes, communication as edges, and packet activity as pulses moving across a stable top-down network map. It is intended for troubleshooting, packet investigation, homelab visibility, and understanding communication patterns. It is not an IDS or threat detection platform.

## GIF
![pacmap demo](demo.gif)

## Input Modes

PacMap supports two workflows in the web app:

- Live Capture: inspect what is happening right now on a local interface.
- Replay PCAP: upload a saved `.pcap` or `.pcapng` file and replay packet flow over time.

The app opens on Live Capture and uses Wireshark-inspired analysis tabs for Whole Network Stats, Conversations, Endpoints, Protocol Hierarchy, and I/O Graphs. PCAP upload and replay live inside the Live Capture tab as an alternate input source.

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

Then use the Live Capture tab and click `Start live capture`.

Raw packet capture usually needs elevated local privileges. On macOS/Linux, run from a shell with the needed privileges, for example:

```bash
sudo npm start -- --iface en0
```

On Windows, run the terminal as Administrator.

## Replay PCAP

Open the web app, choose Live Capture, switch the source to PCAP Replay, and upload a `.pcap` or `.pcapng` file. Then use:

- play
- pause
- restart
- speed control
- timeline scrubber
- label mode controls for raw/resolved IP and MAC labels
- conversations ranking by transferred data

Replay runs in the browser and does not require the Python capture server to be running.

Replay also includes Wireshark-inspired investigation panels for conversations, endpoints, protocol breakdown, name resolution, and I/O timeline activity.

Current replay support is intentionally focused on a useful MVP:

- classic `.pcap`
- basic `.pcapng`
- common Ethernet, raw IP, Linux cooked, and loopback captures
- IPv4 and IPv6 packets
- TCP, UDP, DNS, and other IP packets

Unsupported frames are skipped and counted in the UI.

## Why A Local Helper?

Browsers cannot sniff host network traffic or start privileged packet capture directly. PacMap uses a local Python WebSocket helper with Scapy for live capture, then streams packet summaries to the React app at:

```text
ws://127.0.0.1:8765
```

PCAP replay is different: the browser reads the uploaded file and reuses the same graph visualization without needing live packet access.

## Hand Gestures

PacMap can use MediaPipe hand tracking for graph navigation. Navigation modes are:

```text
Zoom, Rotate, Move
```

- Zoom changes node spacing, not camera distance.
- Rotate changes graph yaw and pitch.
- Move pans the cluster.
- Pointer targets nodes.

Zoom, Rotate, and Move use the same lock flow: hold the gesture stable for 1 second in the background, then the visible ring completes in 0.5 seconds. Any completed navigation lock enters Pointer mode. The lock tolerates normal hand jitter by checking both finger spacing and finger position in the camera frame.

In Pointer mode, thumb-index taps jump directly to navigation modes:

- single tap: Rotate
- double tap: Zoom
- triple tap: Move

Pointer mode also supports node selection lock. Aim at a node and hold steady with the same lock behavior: after the silent stability check, the ring completes and locks that node for inspection. The selected node and its local neighbors stay emphasized until cleared.

Open your hand in Pointer mode to clear the selected node and return to normal pointer targeting.

If tracking is temporarily lost in Pointer mode, PacMap pauses at the last stable pointer/view state. It does not reset the cluster, camera orientation, or current context.


## Development

Frontend only:

```bash
cd client
npm install
npm run dev
```

Client UI conventions:

- Vite resolves `@` to `client/src`.
- shadcn-style UI components live in `client/src/components/ui`.
- Shared utilities live in `client/src/lib`.
- Tailwind CSS is enabled through the Vite client config.

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
