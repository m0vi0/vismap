# pacmap

pacmap is a local 3D packet tracer for host network traffic.

It renders devices as 3D nodes, links communicating devices with edges, and moves packet particles directly along those edges. Nodes grow as they send or receive more data.

## Run

From the repo root:

```bash
npm start
```

The launcher will:

- install frontend dependencies if `client/node_modules` is missing
- build the React app
- start the local Python server
- serve the UI at `http://127.0.0.1:8080`

Open `http://127.0.0.1:8080` in your browser, then click `Start host capture` to begin packet capture.

On macOS/Linux you can also run:

```bash
sudo ./run-pacmap.sh
```

On Windows, run the terminal as Administrator and use `npm start`. Packet capture requires Npcap.

## Why sudo?

Raw packet capture is not available directly from browser permission prompts. Browsers cannot sniff host network traffic or start privileged local processes for security reasons.

pacmap uses a local Python helper with Scapy to capture packets. On macOS and Linux, packet capture usually requires admin privileges, so the launcher should be run with `sudo`. On Windows, run from an Administrator terminal and install Npcap with WinPcap API-compatible mode if Scapy cannot capture packets.

## Pick A Network Interface

By default, pacmap lets Scapy choose the system default capture interface.

To capture another interface:

```bash
npm start -- --iface en1
```

Common examples:

- macOS Wi-Fi: `en0`
- Linux Ethernet: `eth0`
- Linux Wi-Fi: `wlan0`
- Windows Wi-Fi/Ethernet: use the Npcap interface name shown by Scapy

## Open The Browser Automatically

```bash
npm start -- --open
```

If macOS cannot open the browser automatically, open this URL manually:

```text
http://127.0.0.1:8080
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

Server only, after building the client:

```bash
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
