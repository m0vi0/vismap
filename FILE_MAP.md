# File Map

Use this to inspect likely files before broad searching.

## Core App

- `client/src/App.jsx`: main PacMap app. Contains constants, display filter parsing, PCAP/PCAPNG parsing, replay state, live packet ingestion, Three.js graph setup, graph rebuilds, checkpoints, diff mode, time windows, analysis panels, WebSocket handling, and most rendered UI.
- `client/src/App.css`: primary UI styling for the app shell, full-screen graph viewport, filter bar, control dock, checkpoint panel, inspection drawer, analysis panels, timeline, and responsive behavior.
- `client/src/main.jsx`: React entry point that renders `App`.

## Pure Or Separated Logic

- `client/src/checkpointEngine.js`: pure checkpoint/diff helpers. Key exports: `classifyIp`, `serializeCheckpoint`, `computeCheckpointDiff`, `fmtBytes`.
- `client/src/useHandGestures.js`: MediaPipe hand tracking and gesture navigation. Owns script loading, mode switching, pointer targeting, lock progress, orbit/zoom/spread/pan behavior, and overlay drawing.

## Live Capture And Launching

- `server.py`: Python WebSocket server on `127.0.0.1:8765`. Uses Scapy to sniff IP packets, summarize packet metadata, track aggregate node stats, and send `packet`, `nodes`, and `capture_status` messages.
- `scripts/start-pacmap.mjs`: repo-root launcher. Installs client dependencies if missing, chooses Python executable/venv, starts `server.py`, and starts Vite at `http://127.0.0.1:5176`.
- `run-pacmap.sh`: Unix helper for starting the app.

## Config And UI Primitives

- `client/vite.config.js`: Vite config. Uses React, Tailwind, strict host `127.0.0.1`, strict port `5176`, and `@` alias to `client/src`.
- `client/package.json`: client scripts and dependencies.
- `package.json`: repo-root `npm start` entry.
- `client/src/components/ui/*`: shadcn-style primitives and an unused or secondary hero component. Do not assume these drive the current main app.
- `client/src/lib/utils.ts`: `cn` helper for shadcn-style class merging.

## Useful Search Terms

- Capture/replay parsing: `parseCaptureBuffer`, `parseClassicPcap`, `parsePcapng`, `parseLinkLayerPacket`, `prepareReplayPackets`, `LINKTYPE_NAMES`.
- Filtering/path trace: `parseDisplayFilter`, `packetMatchesFilter`, `FILTER_SUGGESTIONS`, `extractPathEndpoints`, `bfsPath`, `pathTrace`.
- Analysis panels: `buildTrafficAnalysis`, `createEmptyAnalysis`, `conversationSort`, `analysisSnapshot`.
- Graph rendering: `rebuildGraphRef`, `snapshotGraphRef`, `nodesRef`, `edgesRef`, `packetsRef`, `nodeStore`, `edgeStore`.
- Checkpoints/diff: `serializeCheckpoint`, `computeCheckpointDiff`, `autoCheckpointMode`, `activeDiff`, `windowDiffResult`, `pacmap_checkpoints`.
- Live WebSocket: `WS_URL`, `start_capture`, `capture_status`, `websocketRef`, `packet_callback`.
- Gestures: `useHandGestures`, `LOCK_STABLE_MS`, `LOCK_PROGRESS_MS`, `TAP_RESOLVE_MS`, `OPEN_HAND_SPREAD`.
- Ports and launch: `5176`, `8765`, `appUrl`, `pythonCommand`.

## Safe Assumptions

- If the task affects user-visible graph behavior, start in `client/src/App.jsx` and `client/src/App.css`.
- If the task affects checkpoint diff math, start in `client/src/checkpointEngine.js`.
- If the task affects hand controls, start in `client/src/useHandGestures.js`.
- If the task affects live capture data shape, update both `server.py` and the `App.jsx` packet handling path.
- If the task affects PCAP replay only, it is probably browser-side in `App.jsx`, not `server.py`.
