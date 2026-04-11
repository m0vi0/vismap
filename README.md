# pacmap

PacMap is a local packet visualizer for live traffic mapping and PCAP replay.

It shows hosts as nodes, communication as edges, and packet activity as pulses moving across a stable top-down network map. It is intended for troubleshooting, packet investigation, homelab visibility, and understanding communication patterns. It is not an IDS or threat detection platform.

## Input Modes

PacMap supports two workflows in the web app:

- Live Capture: inspect what is happening right now on a local interface.
- Replay PCAP: upload a saved `.pcap` or `.pcapng` file and replay packet flow over time.

The app includes separate Live Capture, Replay PCAP, and Instructions tabs. Live traffic appears in the Live tab. Uploaded captures appear in the Replay tab with playback and analysis controls.

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
http://127.0.0.1:5173
```

Then use the Live Capture tab and click `Start live capture`.

Raw packet capture usually needs elevated local privileges. On macOS/Linux, run from a shell with the needed privileges, for example:

```bash
sudo npm start -- --iface en0
```

On Windows, run the terminal as Administrator.

## Replay PCAP

Open the web app and choose the Replay PCAP tab. Upload a `.pcap` or `.pcapng` file, then use:

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
