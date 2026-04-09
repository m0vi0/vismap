# pacmap

pacmap is a local packet map for host network traffic.

It visualizes devices as nodes, links communicating devices with edges, and shows packet activity moving along those connections. Nodes grow as they send or receive more data.

## Run

From the repo root:

```bash
python3 -m venv venv
source venv/bin/activate
pip install websockets scapy
npm install --prefix client
sudo ./run-pacmap.sh
```

The app has two pieces:

- a Python WebSocket capture server, which needs `websockets` and `scapy`
- a Vite frontend at `http://127.0.0.1:5173`

Open `http://127.0.0.1:5173` in your browser, then click `Start host capture` to begin packet capture.

After the setup commands have been run once, start the app on macOS/Linux with:

```bash
sudo ./run-pacmap.sh
```

`run-pacmap.sh` uses `venv/bin/python` when the repo venv exists, so it can find the Python packages installed above.

`npm start` also exists, but it does not install Python packages and it calls `python3` directly. Use it only if the `python3` available to that command already has `websockets` and `scapy` installed:

```bash
npm start
```

On Windows, run the terminal as Administrator, install the Python packages with `pip install websockets scapy`, then use `npm start`. Packet capture requires Npcap.

## Why sudo?

Raw packet capture is not available directly from browser permission prompts. Browsers cannot sniff host network traffic or start privileged local processes for security reasons.

pacmap uses a local Python helper with Scapy to capture packets. On macOS and Linux, packet capture usually requires admin privileges, so the launcher should be run with `sudo`. On Windows, run from an Administrator terminal and install Npcap with WinPcap API-compatible mode if Scapy cannot capture packets.

## Pick A Network Interface

By default, pacmap lets Scapy choose the system default capture interface.

To capture another interface:

```bash
sudo ./run-pacmap.sh --iface en1
```

Common examples:

- macOS Wi-Fi: `en0`
- Linux Ethernet: `eth0`
- Linux Wi-Fi: `wlan0`
- Windows Wi-Fi/Ethernet: use the Npcap interface name shown by Scapy

## Open The Browser Automatically

```bash
sudo ./run-pacmap.sh --open
```

If macOS cannot open the browser automatically, open this URL manually:

```text
http://127.0.0.1:5173
```

## Development

Frontend only:

```bash
cd client
npm install
npm run dev
```

Production build:

```bash
cd client
npm run build
```

Capture server only:

```bash
source venv/bin/activate
python3 server.py
```

## Notes

- The UI connects to the local WebSocket server at `ws://127.0.0.1:8765`.
- No demo traffic is generated. If there is no real host traffic, there will be no nodes.
- Open websites, run `ping 8.8.8.8`, or use the network normally to create traffic.
- If the UI says `Capture server offline`, the Python server is not running.
- If the UI says `Capture blocked`, the server started but packet capture failed. Check the interface name and run with `sudo` or Administrator privileges.

## Tech

- React + Vite
- Three.js
- Framer Motion
- Lucide React
- Python WebSocket server
- Scapy packet capture
