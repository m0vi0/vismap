# Project Context

PacMap is a graph-first network traffic visualizer for live capture and PCAP replay. It helps inspect what changed, what is noisy, and what needs attention by turning packet flow into an interactive 3D graph.

## Stack

- React 19 + Vite client in `client/`.
- Three.js renders the network graph.
- Python WebSocket helper in `server.py` streams live packet summaries from Scapy.
- Browser-side PCAP/PCAPNG parsing reuses the same graph and analysis UI without the Python capture server.
- MediaPipe Hands powers optional gesture navigation.
- Tailwind CSS and shadcn-style primitives are present, but most product UI is custom CSS in `client/src/App.css`.

## Current Priorities

- Keep live capture and PCAP replay stable.
- Preserve checkpoint/diff behavior and Wireshark-like analysis panels.
- Keep the graph readable under packet churn, filters, replay windows, and time-range comparisons.
- Maintain gesture navigation without regressing pointer lock, tap-to-mode switching, or graph orbit/pan/spacing controls.

## Current Pain Points

- `client/src/App.jsx` is large and owns many concerns: parsing, replay, filtering, graph rendering, checkpoints, analysis, WebSocket handling, and UI state.
- Graph state is split across React state, refs, Three.js objects, and derived packet windows.
- Live capture depends on local privileges, correct interface names, and WebSocket availability.
- PCAP support is intentionally limited; unsupported link types or frames are skipped.
- Gesture thresholds are sensitive to jitter and camera framing.

## Constraints

- Live capture uses `ws://127.0.0.1:8765`.
- Vite dev server runs on `http://127.0.0.1:5176` with `strictPort`.
- Replay should work fully in the browser after file upload.
- Keep AI workflow context as plain markdown in the repo.
- Do not add AI databases, embeddings, RAG services, or extra context servers.
- `client/src/Untitled-1.md` appears unrelated to PacMap and should not be treated as project documentation.

## Current Direction

Prefer small extractions of pure logic when needed, similar to `client/src/checkpointEngine.js`. Avoid broad rewrites of `App.jsx` unless the user explicitly asks for a refactor and impact has been checked.
