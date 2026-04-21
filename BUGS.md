# Bugs And Gotchas

## Fragile Areas

- `client/src/App.jsx` is large and state-heavy. Avoid sweeping edits unless the task is explicitly a refactor.
- Live packet ingestion, replay packets, filtered packets, time windows, and graph rebuild refs must stay in sync.
- Three.js objects and React state are mixed through refs. Preserve cleanup paths when touching graph setup or effects.
- Gesture constants in `client/src/useHandGestures.js` are tuned for jitter tolerance. Small threshold changes can break lock progress, pointer selection, or tap mode switching.

## Known Limitations

- Display filters are a small Wireshark-like subset: protocol names, `ip.addr`, `ip.src`, `ip.dst`, `tcp.port`, `udp.port`, `port`, and simple `&&` combinations.
- PCAP replay supports classic PCAP/basic PCAPNG plus common Ethernet, raw IP, Linux cooked, and loopback captures. Unsupported frames are skipped and counted.
- Live capture requires Scapy, a valid interface, and elevated privileges on many systems.
- MediaPipe gesture scripts load from CDN, so gestures can fail without network access.

## Behavior To Preserve

- Live capture WebSocket endpoint is `ws://127.0.0.1:8765`.
- Vite dev URL is `http://127.0.0.1:5176`; launcher and Vite config both assume this.
- Replay should not require the Python capture server.
- Checkpoints persist in `localStorage` under `pacmap_checkpoints`.
- The reference checkpoint persists under `pacmap_reference_checkpoint`.
- Capture status messages use `capture_status`; start requests use `start_capture`.
- Packet summaries should keep `src`, `dst`, `size`, `proto`, `timestamp`, IP/MAC metadata, and port metadata where available.

## Noise

- `client/src/Untitled-1.md` appears unrelated to PacMap. Do not use it as architecture or product context.
