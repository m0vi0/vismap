/**
 * checkpointEngine.js — Pure functions for the PacMap checkpoint/diff system.
 * No React, no Three.js. Safe to unit-test in isolation.
 */

// ── IP Classification ────────────────────────────────────────

/**
 * Classify an IP address by its role/scope.
 * @param {string} ip
 * @returns {'internal'|'external'|'multicast'|'broadcast'|'loopback'|'link-local'|'unknown'}
 */
export function classifyIp(ip) {
  if (!ip) return 'unknown'

  // IPv4
  if (ip.includes('.')) {
    if (ip === '127.0.0.1' || ip.startsWith('127.')) return 'loopback'
    if (ip === '255.255.255.255' || ip.endsWith('.255')) return 'broadcast'
    if (ip.startsWith('224.') || ip.startsWith('239.')) return 'multicast'
    if (ip.startsWith('169.254.')) return 'link-local'
    const parts = ip.split('.').map(Number)
    if (parts[0] === 10) return 'internal'
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return 'internal'
    if (parts[0] === 192 && parts[1] === 168) return 'internal'
    return 'external'
  }

  // IPv6
  if (ip.includes(':')) {
    if (ip === '::1') return 'loopback'
    if (ip.startsWith('fe80:')) return 'link-local'
    if (ip.startsWith('ff')) return 'multicast'
    if (ip.startsWith('fc') || ip.startsWith('fd')) return 'internal'
    return 'external'
  }

  return 'unknown'
}

// ── Serialization ────────────────────────────────────────────

/**
 * Serialize current graph state into a plain checkpoint-ready object.
 * Call this with snapshot copies of nodeStore/edgeStore (no Three.js refs).
 *
 * @param {Map<string, {ip, bytes, packets, mac}>} nodeMap  — plain data map (no Three.js)
 * @param {Map<string, {src, dst, bytes, packets}>} edgeMap — plain data map
 * @param {object} trafficAnalysis — from buildTrafficAnalysis()
 * @returns {{ nodes, edges, protocolSummary, totals, nodeCount, edgeCount }}
 */
export function serializeCheckpoint(nodeMap, edgeMap, trafficAnalysis) {
  // Build peer sets from edge map in one pass
  const peerSets = new Map()
  edgeMap.forEach(({ src, dst }) => {
    if (!peerSets.has(src)) peerSets.set(src, new Set())
    if (!peerSets.has(dst)) peerSets.set(dst, new Set())
    peerSets.get(src).add(dst)
    peerSets.get(dst).add(src)
  })

  const nodes = []
  nodeMap.forEach((n, ip) => {
    const peers = peerSets.get(ip) || new Set()
    nodes.push({
      ip,
      mac: n.mac || '',
      kind: classifyIp(ip),
      bytes: n.bytes,
      packets: n.packets,
      uniquePeers: peers.size,
      peerIds: [...peers],
    })
  })

  const edges = []
  edgeMap.forEach(({ src, dst, bytes, packets }) => {
    edges.push({
      src,
      dst,
      bytes,
      packets,
      isExternal: classifyIp(src) === 'external' || classifyIp(dst) === 'external',
    })
  })

  const protocolSummary = {}
  ;(trafficAnalysis?.protocols || []).forEach(p => {
    protocolSummary[p.proto] = { bytes: p.bytes, packets: p.packets }
  })

  const totals = {
    bytes: trafficAnalysis?.totalBytes || 0,
    packets: nodes.reduce((s, n) => s + n.packets, 0),
  }

  return {
    nodes,
    edges,
    protocolSummary,
    totals,
    nodeCount: nodes.length,
    edgeCount: edges.length,
  }
}

// ── Diff Engine ──────────────────────────────────────────────

/**
 * Compute a structured diff between two serialized checkpoint states.
 * Pure function — no side effects, no rendering.
 *
 * @param {object} base    — serialized checkpoint state (has .nodes[], .edges[], .protocolSummary)
 * @param {object} compare — serialized checkpoint state (same shape)
 * @returns {DiffResult}
 */
export function computeCheckpointDiff(base, compare) {
  // Index nodes by IP
  const baseNodes = new Map(base.nodes.map(n => [n.ip, n]))
  const compareNodes = new Map(compare.nodes.map(n => [n.ip, n]))

  // Index edges by canonical key
  const edgeKey = (e) => `${e.src}<->${e.dst}`
  const baseEdges = new Map(base.edges.map(e => [edgeKey(e), e]))
  const compareEdges = new Map(compare.edges.map(e => [edgeKey(e), e]))

  const addedNodes = []
  const removedNodes = []
  const changedNodes = []

  compareNodes.forEach((n, ip) => {
    if (!baseNodes.has(ip)) addedNodes.push(n)
  })

  baseNodes.forEach((n, ip) => {
    if (!compareNodes.has(ip)) removedNodes.push(n)
  })

  compareNodes.forEach((curr, ip) => {
    const prev = baseNodes.get(ip)
    if (!prev) return // already in addedNodes

    const bytesDelta = curr.bytes - prev.bytes
    const packetsDelta = curr.packets - prev.packets
    const uniquePeersDelta = curr.uniquePeers - prev.uniquePeers

    // Only include meaningfully changed nodes
    if (Math.abs(bytesDelta) < 1024 && packetsDelta === 0 && uniquePeersDelta === 0) return

    const prevPeers = new Set(prev.peerIds)
    const currPeers = new Set(curr.peerIds)
    const addedPeers = curr.peerIds.filter(p => !prevPeers.has(p))
    const removedPeers = prev.peerIds.filter(p => !currPeers.has(p))

    let reason = '~ activity'
    if (addedPeers.length > 0 || removedPeers.length > 0) {
      const net = addedPeers.length - removedPeers.length
      reason = `Δ peers ${net >= 0 ? '+' : ''}${net}`
    }
    if (Math.abs(bytesDelta) > 100_000) {
      reason = bytesDelta > 0 ? `↑ ${fmtBytes(bytesDelta)}` : `↓ ${fmtBytes(bytesDelta)}`
    }

    changedNodes.push({
      ip,
      bytesDelta,
      packetsDelta,
      uniquePeersDelta,
      addedPeers,
      removedPeers,
      reason,
    })
  })

  // Sort changed nodes by magnitude of change
  changedNodes.sort((a, b) => Math.abs(b.bytesDelta) - Math.abs(a.bytesDelta))

  const addedEdges = []
  const removedEdges = []

  compareEdges.forEach((e, key) => {
    if (!baseEdges.has(key)) addedEdges.push(e)
  })
  baseEdges.forEach((e, key) => {
    if (!compareEdges.has(key)) removedEdges.push(e)
  })

  // Protocol deltas
  const allProtos = new Set([
    ...Object.keys(base.protocolSummary || {}),
    ...Object.keys(compare.protocolSummary || {}),
  ])
  const protocolDeltas = []
  allProtos.forEach(proto => {
    const b = base.protocolSummary?.[proto] || { bytes: 0, packets: 0 }
    const c = compare.protocolSummary?.[proto] || { bytes: 0, packets: 0 }
    const pktsDelta = c.packets - b.packets
    const bytesDelta = c.bytes - b.bytes
    if (pktsDelta === 0 && bytesDelta === 0) return
    const pctChange = b.packets > 0 ? ((c.packets - b.packets) / b.packets) * 100 : 100
    protocolDeltas.push({
      proto,
      basePkts: b.packets,
      currPkts: c.packets,
      pktsDelta,
      baseBytes: b.bytes,
      currBytes: c.bytes,
      bytesDelta,
      pctChange: Math.round(pctChange),
    })
  })
  protocolDeltas.sort((a, b) => Math.abs(b.pktsDelta) - Math.abs(a.pktsDelta))

  return {
    addedNodes,
    removedNodes,
    addedEdges,
    removedEdges,
    changedNodes,
    protocolDeltas,
    summary: {
      addedNodeCount: addedNodes.length,
      removedNodeCount: removedNodes.length,
      addedEdgeCount: addedEdges.length,
      removedEdgeCount: removedEdges.length,
      changedNodeCount: changedNodes.length,
      significantProtocolChanges: protocolDeltas.filter(d => Math.abs(d.pctChange) > 10).length,
    },
  }
}

// ── Formatting ───────────────────────────────────────────────

/**
 * Format a byte count into a human-readable string.
 * @param {number} n
 * @returns {string}
 */
export function fmtBytes(n) {
  const abs = Math.abs(n)
  const sign = n < 0 ? '-' : n > 0 ? '+' : ''
  if (abs >= 1_048_576) return `${sign}${(abs / 1_048_576).toFixed(1)} MB`
  if (abs >= 1024) return `${sign}${(abs / 1024).toFixed(1)} KB`
  return `${sign}${abs} B`
}
