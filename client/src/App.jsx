import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import { classifyIp, serializeCheckpoint, computeCheckpointDiff, fmtBytes } from './checkpointEngine.js'
import './App.css'

const WS_URL = 'ws://127.0.0.1:8765'
const MAX_PACKET_PARTICLES = 420
const NODE_LIMIT = 18
const LIVE_PACKET_HISTORY_LIMIT = 2000
const LIVE_PACKET_UI_FLUSH_MS = 1000
const ANALYSIS_PACKET_WINDOW = 2000
const TABLE_ROW_LIMIT = 80
const LARGE_TABLE_ROW_LIMIT = 80
const ANALYSIS_SNAPSHOT_MS = 1000
const LIVE_GRAPH_REBUILD_MS = 350
const TARGET_PIXEL_TOLERANCE = 42
const REPLAY_TICK_MS = 80
const MIN_CAMERA_ZOOM = 0.55
const MAX_CAMERA_ZOOM = 2.5
const DEFAULT_CAMERA_ZOOM = 1
const ORBIT_TARGET = new THREE.Vector3(0, 0, 0)
const MIN_LAYOUT_SPREAD = 0.5
const MAX_LAYOUT_SPREAD = 2.25
const PAN_BOUND = 320

const PROTOCOLS = {
  TCP: { color: 0x60a5fa, css: '#60a5fa', label: 'TCP' },
  UDP: { color: 0x34d399, css: '#34d399', label: 'UDP' },
  DNS: { color: 0xfacc15, css: '#facc15', label: 'DNS' },
  ARP: { color: 0xfb7185, css: '#fb7185', label: 'ARP' },
  OTHER: { color: 0xc084fc, css: '#c084fc', label: 'Other' },
}

const TABS = {
  live: 'Live Capture',
}

const LINKTYPE_NAMES = {
  0: 'BSD loopback',
  1: 'Ethernet',
  101: 'Raw IP',
  113: 'Linux cooked v1',
  276: 'Linux cooked v2',
}

const LABEL_MODES = {
  resolvedIp: 'Resolved IP',
  rawIp: 'Raw IP',
  rawMac: 'MAC',
  resolvedMac: 'Resolved MAC',
  off: 'Labels off',
}

function byteLabel(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function edgeKey(src, dst) {
  return [src, dst].sort().join('<>')
}

function clampZoom(value) {
  return THREE.MathUtils.clamp(value, MIN_CAMERA_ZOOM, MAX_CAMERA_ZOOM)
}

function normalizeTimestamp(timestamp, fallback) {
  const value = Number(timestamp)
  return Number.isFinite(value) ? value : fallback
}

function packetId(source, index) {
  return `${source}-${index}`
}

function makePacket(src, dst, size, proto, timestamp, metadata = {}) {
  return {
    type: 'packet',
    src,
    dst,
    size,
    proto: proto || 'OTHER',
    timestamp,
    ...metadata,
  }
}

function normalizePacket(packet, source, index) {
  return {
    id: packet.id || packetId(source, index),
    timestamp: Number.isFinite(Number(packet.timestamp)) ? Number(packet.timestamp) : Date.now() / 1000,
    size: Number(packet.size) || 0,
    proto: String(packet.proto || 'OTHER').toUpperCase(),
    ...packet,
  }
}

const FILTER_SUGGESTIONS = [
  'tcp', 'udp', 'dns', 'http', 'arp', 'other',
  'ip.addr == ', 'ip.src == ', 'ip.dst == ',
  'tcp.port == ', 'udp.port == ', 'port == ',
]

function parseDisplayFilter(expression) {
  const raw = expression.trim()
  if (!raw) return { raw, type: 'all' }

  // Compound AND: split on &&, parse each part independently
  if (raw.includes('&&')) {
    const parts = raw.split('&&').map(p => p.trim())
    const parsed = parts.map(part => {
      const result = parseDisplayFilter(part)
      if (result.type === 'all' || result.type === 'compound') throw new Error('Invalid compound filter part: ' + part)
      return result
    })
    return { raw, type: 'compound', parts: parsed }
  }

  const lower = raw.toLowerCase()
  if (['tcp', 'udp', 'dns', 'http', 'arp', 'other'].includes(lower)) {
    return { raw, type: 'protocol', value: lower.toUpperCase() }
  }

  const match = lower.match(/^(ip\.addr|ip\.src|ip\.dst|tcp\.port|udp\.port|port)\s*==\s*([a-z0-9:.:-]+)$/i)
  if (!match) throw new Error('Unsupported filter. Try tcp, dns, ip.addr == 192.168.1.10, or tcp.port == 443.')

  const [, field, value] = match
  if (field.endsWith('port') || field === 'port') {
    const port = Number(value)
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Port filters need a value from 0 to 65535.')
    return { raw, type: 'field', field, value: port }
  }

  return { raw, type: 'field', field, value }
}

function packetMatchesFilter(packet, filter) {
  if (!filter || filter.type === 'all') return true
  if (filter.type === 'compound') return filter.parts.every(p => packetMatchesFilter(packet, p))
  const proto = String(packet.proto || '').toUpperCase()
  const src = packet.srcIp || packet.src
  const dst = packet.dstIp || packet.dst
  const srcPort = Number(packet.srcPort)
  const dstPort = Number(packet.dstPort)

  if (filter.type === 'protocol') {
    if (filter.value === 'HTTP') return proto === 'TCP' && [80, 8000, 8080].includes(srcPort || dstPort)
    return proto === filter.value
  }

  if (filter.field === 'ip.addr') return src === filter.value || dst === filter.value
  if (filter.field === 'ip.src') return src === filter.value
  if (filter.field === 'ip.dst') return dst === filter.value
  if (filter.field === 'tcp.port') return proto === 'TCP' && (srcPort === filter.value || dstPort === filter.value)
  if (filter.field === 'udp.port') return proto === 'UDP' && (srcPort === filter.value || dstPort === filter.value)
  if (filter.field === 'port') return srcPort === filter.value || dstPort === filter.value
  return true
}

// Returns {src, dst} if filter is a compound containing both ip.src and ip.dst parts; else null.
function extractPathEndpoints(filter) {
  if (!filter || filter.type !== 'compound') return null
  const srcPart = filter.parts.find(p => p.field === 'ip.src')
  const dstPart = filter.parts.find(p => p.field === 'ip.dst')
  if (srcPart && dstPart) return { src: srcPart.value, dst: dstPart.value }
  return null
}

// Pure BFS over adjacency Map<string, Set<string>>. Returns IP array (shortest path) or null.
function bfsPath(src, dst, adjacency) {
  if (!adjacency.has(src) || !adjacency.has(dst)) return null
  if (src === dst) return [src]
  const queue = [[src]]
  const visited = new Set([src])
  while (queue.length) {
    const path = queue.shift()
    const node = path[path.length - 1]
    for (const neighbor of (adjacency.get(node) || [])) {
      if (neighbor === dst) return [...path, neighbor]
      if (!visited.has(neighbor)) {
        visited.add(neighbor)
        queue.push([...path, neighbor])
      }
    }
  }
  return null
}

function formatBytes(b) {
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)}MB`
  if (b >= 1024) return `${(b / 1024).toFixed(1)}KB`
  return `${b}B`
}

function packetInfo(packet) {
  const proto = packet.proto || 'OTHER'
  const ports = packet.srcPort || packet.dstPort ? ` ${packet.srcPort || '?'} -> ${packet.dstPort || '?'}` : ''
  if (proto === 'DNS') return `DNS${ports}`
  if (proto === 'TCP' || proto === 'UDP') return `${proto}${ports}`
  if (proto === 'ARP') return 'ARP who-has / is-at'
  return proto
}

function formatMac(view, offset) {
  const bytes = []
  for (let index = 0; index < 6; index += 1) {
    bytes.push(view.getUint8(offset + index).toString(16).padStart(2, '0'))
  }
  return bytes.join(':')
}

function formatIpv6(view, offset) {
  const groups = []
  for (let index = 0; index < 8; index += 1) {
    groups.push(view.getUint16(offset + index * 2, false).toString(16))
  }
  return groups.join(':')
}

function parseIpv4Header(view, offset, capturedLength, timestamp) {
  if (offset + 20 > capturedLength) return null

  const versionIhl = view.getUint8(offset)
  const version = versionIhl >> 4
  const ihl = (versionIhl & 0x0f) * 4
  if (version !== 4 || ihl < 20 || offset + ihl > capturedLength) return null

  const totalLength = view.getUint16(offset + 2, false)
  const protocolNumber = view.getUint8(offset + 9)
  const src = [
    view.getUint8(offset + 12),
    view.getUint8(offset + 13),
    view.getUint8(offset + 14),
    view.getUint8(offset + 15),
  ].join('.')
  const dst = [
    view.getUint8(offset + 16),
    view.getUint8(offset + 17),
    view.getUint8(offset + 18),
    view.getUint8(offset + 19),
  ].join('.')
  const size = totalLength || Math.max(0, capturedLength - offset)

  let proto = 'OTHER'
  let srcPort = null
  let dstPort = null
  if (protocolNumber === 6) proto = 'TCP'
  if (protocolNumber === 17) {
    proto = 'UDP'
  }
  if ((protocolNumber === 6 || protocolNumber === 17) && offset + ihl + 4 <= capturedLength) {
    srcPort = view.getUint16(offset + ihl, false)
    dstPort = view.getUint16(offset + ihl + 2, false)
    if (protocolNumber === 17 && (srcPort === 53 || dstPort === 53)) {
      proto = 'DNS'
    }
  }

  return makePacket(src, dst, size, proto, timestamp, { srcIp: src, dstIp: dst, srcPort, dstPort })
}

function parseIpv6Header(view, offset, capturedLength, timestamp) {
  if (offset + 40 > capturedLength) return null

  const version = view.getUint8(offset) >> 4
  if (version !== 6) return null

  const payloadLength = view.getUint16(offset + 4, false)
  const nextHeader = view.getUint8(offset + 6)
  const src = formatIpv6(view, offset + 8)
  const dst = formatIpv6(view, offset + 24)
  const size = payloadLength + 40

  let proto = 'OTHER'
  let srcPort = null
  let dstPort = null
  if (nextHeader === 6) proto = 'TCP'
  if (nextHeader === 17) {
    proto = 'UDP'
  }
  if ((nextHeader === 6 || nextHeader === 17) && offset + 44 <= capturedLength) {
    srcPort = view.getUint16(offset + 40, false)
    dstPort = view.getUint16(offset + 42, false)
    if (nextHeader === 17 && (srcPort === 53 || dstPort === 53)) proto = 'DNS'
  }

  return makePacket(src, dst, size, proto, timestamp, { srcIp: src, dstIp: dst, srcPort, dstPort })
}

function parseIpPacket(view, offset, capturedLength, timestamp) {
  if (offset >= capturedLength) return null

  const version = view.getUint8(offset) >> 4
  if (version === 4) return parseIpv4Header(view, offset, capturedLength, timestamp)
  if (version === 6) return parseIpv6Header(view, offset, capturedLength, timestamp)
  return null
}

function withMacMetadata(packet, srcMac, dstMac) {
  if (!packet) return null
  return {
    ...packet,
    srcMac,
    dstMac,
  }
}

function parseArpPacket(view, offset, capturedLength, timestamp, srcMac, dstMac) {
  if (offset + 28 > capturedLength) return null

  const protocolType = view.getUint16(offset + 2, false)
  const hardwareSize = view.getUint8(offset + 4)
  const protocolSize = view.getUint8(offset + 5)
  if (protocolType !== 0x0800 || hardwareSize !== 6 || protocolSize !== 4) return null

  const senderMac = formatMac(view, offset + 8)
  const senderIp = [
    view.getUint8(offset + 14),
    view.getUint8(offset + 15),
    view.getUint8(offset + 16),
    view.getUint8(offset + 17),
  ].join('.')
  const targetMac = formatMac(view, offset + 18)
  const targetIp = [
    view.getUint8(offset + 24),
    view.getUint8(offset + 25),
    view.getUint8(offset + 26),
    view.getUint8(offset + 27),
  ].join('.')

  return makePacket(senderIp, targetIp, 28, 'ARP', timestamp, {
    srcIp: senderIp,
    dstIp: targetIp,
    srcMac: senderMac || srcMac,
    dstMac: targetMac || dstMac,
  })
}

function parseEthernetPacket(view, offset, capturedLength, timestamp) {
  if (capturedLength < 14 || offset + capturedLength > view.byteLength) return null

  const dstMac = formatMac(view, offset)
  const srcMac = formatMac(view, offset + 6)
  let etherTypeOffset = offset + 12
  let etherType = view.getUint16(etherTypeOffset, false)
  let ipOffset = offset + 14

  if (etherType === 0x8100 && capturedLength >= 18) {
    etherTypeOffset += 4
    etherType = view.getUint16(etherTypeOffset, false)
    ipOffset += 4
  }

  if (etherType === 0x0800 || etherType === 0x86dd) {
    const packet = parseIpPacket(view, ipOffset, offset + capturedLength, timestamp)
    if (!packet) return null
    const resolvedNames = etherType === 0x0800 ? extractDnsNames(view, packet, ipOffset, offset + capturedLength) : {}
    return withMacMetadata({ ...packet, resolvedNames }, srcMac, dstMac)
  }
  if (etherType === 0x0806) {
    return parseArpPacket(view, ipOffset, offset + capturedLength, timestamp, srcMac, dstMac)
  }
  return null
}

function parseLinkLayerPacket(view, offset, capturedLength, timestamp, linkType) {
  if (capturedLength <= 0 || offset + capturedLength > view.byteLength) return null

  const endOffset = offset + capturedLength
  if (linkType === 1) return parseEthernetPacket(view, offset, capturedLength, timestamp)
  if (linkType === 101) return parseIpPacket(view, offset, endOffset, timestamp)

  if (linkType === 113 && capturedLength >= 16) {
    const protocol = view.getUint16(offset + 14, false)
    if (protocol === 0x0800 || protocol === 0x86dd) {
      return parseIpPacket(view, offset + 16, endOffset, timestamp)
    }
  }

  if (linkType === 276 && capturedLength >= 20) {
    const protocol = view.getUint16(offset, false)
    if (protocol === 0x0800 || protocol === 0x86dd) {
      return parseIpPacket(view, offset + 20, endOffset, timestamp)
    }
  }

  if (linkType === 0 && capturedLength >= 4) {
    return parseIpPacket(view, offset + 4, endOffset, timestamp)
  }

  return null
}

function linkTypeLabel(linkType) {
  return `${LINKTYPE_NAMES[linkType] || 'link type'} ${linkType}`
}

function dnsNameAt(view, offset, packetEnd, baseOffset = 0) {
  const labels = []
  let cursor = offset
  let jumped = false
  let nextOffset = offset
  let guard = 0

  while (cursor < packetEnd && guard < 32) {
    guard += 1
    const length = view.getUint8(cursor)
    if (length === 0) {
      if (!jumped) nextOffset = cursor + 1
      return { name: labels.join('.'), nextOffset }
    }
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= packetEnd) return null
      const pointer = ((length & 0x3f) << 8) | view.getUint8(cursor + 1)
      if (!jumped) nextOffset = cursor + 2
      cursor = baseOffset + pointer
      jumped = true
      continue
    }
    const labelStart = cursor + 1
    const labelEnd = labelStart + length
    if (labelEnd > packetEnd) return null
    labels.push(
      Array.from({ length }, (_, index) => String.fromCharCode(view.getUint8(labelStart + index))).join(''),
    )
    cursor = labelEnd
    if (!jumped) nextOffset = cursor
  }

  return null
}

function extractDnsNames(view, packet, ipOffset, capturedLength) {
  if (packet.proto !== 'DNS' || !packet.srcPort || !packet.dstPort) return {}

  const udpOffset = ipOffset + ((view.getUint8(ipOffset) & 0x0f) * 4)
  const dnsOffset = udpOffset + 8
  const packetEnd = capturedLength
  if (dnsOffset + 12 > packetEnd) return {}

  const qdCount = view.getUint16(dnsOffset + 4, false)
  const anCount = view.getUint16(dnsOffset + 6, false)
  let cursor = dnsOffset + 12
  let queryName = ''
  const hostnames = {}

  for (let index = 0; index < qdCount; index += 1) {
    const parsed = dnsNameAt(view, cursor, packetEnd, dnsOffset)
    if (!parsed) return {}
    queryName = parsed.name || queryName
    cursor = parsed.nextOffset + 4
  }

  for (let index = 0; index < anCount; index += 1) {
    const parsed = dnsNameAt(view, cursor, packetEnd, dnsOffset)
    if (!parsed || parsed.nextOffset + 10 > packetEnd) return hostnames
    cursor = parsed.nextOffset
    const recordType = view.getUint16(cursor, false)
    const dataLength = view.getUint16(cursor + 8, false)
    cursor += 10
    if (cursor + dataLength > packetEnd) return hostnames

    const name = parsed.name || queryName
    if (recordType === 1 && dataLength === 4) {
      const ip = [
        view.getUint8(cursor),
        view.getUint8(cursor + 1),
        view.getUint8(cursor + 2),
        view.getUint8(cursor + 3),
      ].join('.')
      if (name) hostnames[ip] = name
    }
    if (recordType === 28 && dataLength === 16 && name) {
      hostnames[formatIpv6(view, cursor)] = name
    }
    cursor += dataLength
  }

  return hostnames
}

function parseClassicPcap(view) {
  if (view.byteLength < 24) return null

  const magicLe = view.getUint32(0, true)
  const magicBe = view.getUint32(0, false)
  let littleEndian = true
  let timestampDivisor = 1_000_000

  if (magicLe === 0xa1b2c3d4) littleEndian = true
  else if (magicBe === 0xa1b2c3d4) littleEndian = false
  else if (magicLe === 0xa1b23c4d) {
    littleEndian = true
    timestampDivisor = 1_000_000_000
  } else if (magicBe === 0xa1b23c4d) {
    littleEndian = false
    timestampDivisor = 1_000_000_000
  } else {
    return null
  }

  const linkType = view.getUint32(20, littleEndian)
  const packets = []
  const linkTypes = new Set([linkType])
  let skipped = 0
  let offset = 24

  while (offset + 16 <= view.byteLength) {
    const tsSec = view.getUint32(offset, littleEndian)
    const tsFrac = view.getUint32(offset + 4, littleEndian)
    const capturedLength = view.getUint32(offset + 8, littleEndian)
    offset += 16

    if (capturedLength <= 0 || offset + capturedLength > view.byteLength) {
      skipped += 1
      break
    }

    const packet = parseLinkLayerPacket(
      view,
      offset,
      capturedLength,
      tsSec + tsFrac / timestampDivisor,
      linkType,
    )
    if (packet) packets.push(packet)
    else skipped += 1

    offset += capturedLength
  }

  return { packets, skipped, format: 'pcap', linkTypes: [...linkTypes] }
}

function parsePcapng(view) {
  if (view.byteLength < 12 || view.getUint32(0, true) !== 0x0a0d0d0a) return null

  const packets = []
  const interfaces = []
  const linkTypes = new Set()
  let littleEndian = true
  let skipped = 0
  let offset = 0

  while (offset + 12 <= view.byteLength) {
    const blockType = view.getUint32(offset, littleEndian)
    const blockLength = view.getUint32(offset + 4, littleEndian)
    if (blockLength < 12 || offset + blockLength > view.byteLength) break

    if (blockType === 0x0a0d0d0a && blockLength >= 28) {
      const byteOrderMagic = view.getUint32(offset + 8, true)
      littleEndian = byteOrderMagic === 0x1a2b3c4d
    } else if (blockType === 0x00000001 && blockLength >= 20) {
      const linkType = view.getUint16(offset + 8, littleEndian)
      interfaces.push({ linkType, tsResolution: 1_000_000 })
      linkTypes.add(linkType)
    } else if (blockType === 0x00000006 && blockLength >= 32) {
      const interfaceId = view.getUint32(offset + 8, littleEndian)
      const timestampHigh = view.getUint32(offset + 12, littleEndian)
      const timestampLow = view.getUint32(offset + 16, littleEndian)
      const capturedLength = view.getUint32(offset + 20, littleEndian)
      const packetOffset = offset + 28
      const iface = interfaces[interfaceId] || interfaces[0] || { linkType: 1, tsResolution: 1_000_000 }
      linkTypes.add(iface.linkType)

      if (packetOffset + capturedLength <= offset + blockLength - 4) {
        const timestamp = (timestampHigh * 2 ** 32 + timestampLow) / iface.tsResolution
        const packet = parseLinkLayerPacket(view, packetOffset, capturedLength, timestamp, iface.linkType)
        if (packet) packets.push(packet)
        else skipped += 1
      } else {
        skipped += 1
      }
    }

    offset += blockLength
  }

  return { packets, skipped, format: 'pcapng', linkTypes: [...linkTypes] }
}

function prepareReplayPackets(packets) {
  if (!packets.length) return []
  const firstTimestamp = Math.min(...packets.map((packet, index) => normalizeTimestamp(packet.timestamp, index)))

  return packets
    .map((packet, index) => ({
      ...packet,
      replayTime: Math.max(0, normalizeTimestamp(packet.timestamp, index) - firstTimestamp),
    }))
    .sort((a, b) => a.replayTime - b.replayTime)
}

function parseCaptureBuffer(buffer) {
  const view = new DataView(buffer)
  const result = parseClassicPcap(view) || parsePcapng(view)
  if (!result) throw new Error('Unsupported capture format. Use common IPv4 or IPv6 .pcap/.pcapng files.')

  const packets = prepareReplayPackets(result.packets)
  const duration = packets.length ? packets[packets.length - 1].replayTime : 0

  return {
    ...result,
    packets,
    duration,
  }
}

function parseIpv4(ip) {
  const parts = String(ip).split('.').map((part) => Number(part))
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null
  }

  return parts
}

function isPrivateIpv4(ip) {
  const parts = parseIpv4(ip)
  if (!parts) return false

  const [a, b] = parts
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

function isBcastIp(ip) {
  return ip === '255.255.255.255' || (ip.includes('.') && ip.endsWith('.255'))
}

function isMcastIp(ip) {
  return ip.startsWith('224.') || ip.startsWith('239.') || ip.startsWith('ff0') || ip.startsWith('ff02')
}

function packetProtocolGroup(packet) {
  const proto = String(packet.proto || '').toUpperCase()
  const dst = packet.dst || packet.dstIp || ''
  if (isBcastIp(dst)) return 'BCAST'
  if (isMcastIp(dst)) return 'MCAST'
  return proto || 'OTHER'
}

function createEmptyAnalysis() {
  return {
    conversations: [],
    endpoints: [],
    protocols: [],
    hostnames: new Map(),
    macNames: new Map(),
    timelineBuckets: Array.from({ length: 40 }, () => 0),
    maxBucket: 1,
    totalBytes: 0,
    throughput: 0,
  }
}

function buildTrafficAnalysis(packets, replayMeta, conversationSort = 'bytes') {
  const conversations = new Map()
  const endpoints = new Map()
  const protocols = new Map()
  const hostnames = new Map()
  const macNames = new Map()
  const timelineBuckets = Array.from({ length: 40 }, () => 0)
  const duration = Math.max(replayMeta?.duration || 0, 0.1)
  let totalBytes = 0
  let latestTimestamp = 0

  packets.forEach((packet) => {
    const size = Number(packet.size) || 0
    const proto = packet.proto || 'OTHER'
    const src = packet.src || packet.srcIp
    const dst = packet.dst || packet.dstIp
    const timestamp = Number(packet.timestamp) || 0
    const packetTime = Number.isFinite(Number(packet.replayTime)) ? Number(packet.replayTime) : timestamp
    if (!src || !dst) return

    totalBytes += size
    latestTimestamp = Math.max(latestTimestamp, timestamp)

    Object.entries(packet.resolvedNames || {}).forEach(([ip, name]) => {
      if (name) hostnames.set(ip, name)
    })
    if (packet.srcMac && packet.srcIp) macNames.set(packet.srcMac, packet.srcIp)
    if (packet.dstMac && packet.dstIp) macNames.set(packet.dstMac, packet.dstIp)

    const endpointsKey = [src, dst].sort().join('<>')
    const convoKey = `${endpointsKey}<${proto}>`
    const conversation = conversations.get(convoKey) || {
      key: convoKey,
      src,
      dst,
      proto,
      bytes: 0,
      packets: 0,
      first: packetTime,
      last: packetTime,
    }
    conversation.bytes += size
    conversation.packets += 1
    conversation.first = Math.min(conversation.first, packetTime)
    conversation.last = Math.max(conversation.last, packetTime)
    conversations.set(convoKey, conversation)

      ;[src, dst].forEach((ip) => {
        const endpoint = endpoints.get(ip) || { ip, bytes: 0, packets: 0, protocols: new Set(), mac: '' }
        endpoint.bytes += size
        endpoint.packets += 1
        endpoint.protocols.add(proto)
        if (ip === packet.srcIp && packet.srcMac) endpoint.mac = packet.srcMac
        if (ip === packet.dstIp && packet.dstMac) endpoint.mac = packet.dstMac
        endpoints.set(ip, endpoint)
      })

    const protocol = protocols.get(proto) || { proto, bytes: 0, packets: 0 }
    protocol.bytes += size
    protocol.packets += 1
    protocols.set(proto, protocol)

    const bucket = Math.min(timelineBuckets.length - 1, Math.floor((packetTime / duration) * timelineBuckets.length))
    timelineBuckets[bucket] += size
  })

  const sortedConversations = [...conversations.values()].map((conversation) => ({
    ...conversation,
    duration: Math.max(0.001, conversation.last - conversation.first),
    rate: conversation.bytes / Math.max(0.001, conversation.last - conversation.first),
  }))
  sortedConversations.sort((a, b) => {
    if (conversationSort === 'packets') return b.packets - a.packets
    if (conversationSort === 'rate') return b.rate - a.rate
    if (conversationSort === 'recent') return b.last - a.last
    return b.bytes - a.bytes
  })

  const throughput = latestTimestamp
    ? packets
      .filter((packet) => latestTimestamp - (Number(packet.timestamp) || 0) <= 5)
      .reduce((total, packet) => total + (Number(packet.size) || 0), 0) / 5
    : 0

  return {
    conversations: sortedConversations,
    endpoints: [...endpoints.values()]
      .map((endpoint) => ({ ...endpoint, protocols: [...endpoint.protocols].join(', ') }))
      .sort((a, b) => b.bytes - a.bytes),
    protocols: [...protocols.values()].sort((a, b) => b.bytes - a.bytes),
    hostnames,
    macNames,
    timelineBuckets,
    maxBucket: Math.max(...timelineBuckets, 1),
    totalBytes,
    throughput,
  }
}

/**
 * Serialize a packet array into a checkpoint-compatible snapshot.
 * Used for time-window comparison. Pure — no side effects.
 */
function buildWindowSnapshot(packets) {
  const analysis = buildTrafficAnalysis(packets, null, 'bytes')
  const nodeMap = new Map(analysis.endpoints.map(ep =>
    [ep.ip, { bytes: ep.bytes, packets: ep.packets, mac: ep.mac || '' }]
  ))
  const edgeMap = new Map()
  analysis.conversations.forEach(conv => {
    const key = [conv.src, conv.dst].sort().join('<->')
    if (!edgeMap.has(key)) edgeMap.set(key, { src: conv.src, dst: conv.dst, bytes: conv.bytes, packets: conv.packets })
  })
  return serializeCheckpoint(nodeMap, edgeMap, analysis)
}

function formatReplayTime(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '0:00'
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  return `${m}:${s.toString().padStart(2, '0')}`
}

function formatWindowDuration(range) {
  const d = range.end - range.start
  if (d < 60) return `${d.toFixed(0)}s`
  return `${(d / 60).toFixed(1)}min`
}

function makeTextSprite(text) {
  const canvas = document.createElement('canvas')
  canvas.width = 768
  canvas.height = 192

  const ctx = canvas.getContext('2d')
  ctx.clearRect(0, 0, canvas.width, canvas.height)
  ctx.font = '500 62px "SF Mono", "Roboto Mono", "IBM Plex Mono", ui-monospace, monospace'
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.lineWidth = 5
  ctx.strokeStyle = 'rgba(5, 5, 5, 0.86)'
  ctx.strokeText(text, 384, 96)
  ctx.shadowColor = 'rgba(0, 0, 0, 0.88)'
  ctx.shadowBlur = 8
  ctx.shadowOffsetY = 2
  ctx.fillStyle = '#f7fbfa'
  ctx.fillText(text, 384, 96)

  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: false })
  const sprite = new THREE.Sprite(material)
  sprite.scale.set(150, 38, 1)
  return sprite
}

function updateTextSprite(sprite, text) {
  const nextSprite = makeTextSprite(text)
  const previousMap = sprite.material.map
  sprite.material.map = nextSprite.material.map
  sprite.material.needsUpdate = true
  previousMap?.dispose()
  nextSprite.material.dispose()
}

function randomPosition(index) {
  const angle = index * 2.399963
  const tilt = index * 1.734 + 0.72
  const radius = 120 + (index % 11) * 17
  return {
    x: Math.cos(angle) * Math.sin(tilt) * radius,
    y: Math.cos(tilt) * radius * 0.82,
    z: Math.sin(angle) * Math.sin(tilt) * radius,
  }
}

function hashString(value) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return hash >>> 0
}

function subnetKey(ip) {
  if (isPrivateIpv4(ip)) return ip.split('.').slice(0, 3).join('.')
  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':')
  if (ip.includes('.')) return ip.split('.').slice(0, 2).join('.')
  return ip
}

function clusterAnchor(ip, dnsIps) {
  const isBcast = isBcastIp(ip)
  const isMcast = isMcastIp(ip)
  const isDns = dnsIps ? dnsIps.has(ip) : false
  const isLocal = isPrivateIpv4(ip)

  let radius
  if (isBcast || isMcast) radius = 200
  else if (isDns) radius = 40
  else if (isLocal) radius = 100
  else radius = 165

  const hash = hashString(subnetKey(ip))
  const theta = ((hash & 0xffff) / 0xffff) * Math.PI * 2
  const spread = (isBcast || isMcast || isDns) ? 0.2 : 0.6
  const z = (((hash >>> 16) & 0xffff) / 0xffff) * spread * 2 - spread
  const ring = Math.sqrt(Math.max(0, 1 - z * z))

  return {
    x: Math.cos(theta) * ring * radius,
    y: z * radius,
    z: Math.sin(theta) * ring * radius,
  }
}

function nodeMass(node) {
  return THREE.MathUtils.clamp(1 + Math.log10(node.bytes + 1) * 0.7 + Math.sqrt(node.packets) * 0.025, 1, 9)
}

function nodeRadius(node) {
  return THREE.MathUtils.clamp(1.45 + nodeMass(node) * 0.18, 1.7, 3.1)
}

function nodeRenderScale(node) {
  return node.renderScale || 1
}

function renderedNodeRadius(node) {
  return nodeRadius(node) * nodeRenderScale(node)
}

function pulseRadius(node) {
  return THREE.MathUtils.clamp(node.recentBytes / 4500, 0, 1.4) * 1.2
}

function collisionNodeRadius(node) {
  return renderedNodeRadius(node) + pulseRadius(node)
}

export default function App() {
  const mountRef = useRef(null)
  const nodesRef = useRef(new Map())
  const edgesRef = useRef(new Map())
  const packetsRef = useRef([])
  const livePacketsRef = useRef([])
  const livePacketFlushRef = useRef(null)
  const frameRef = useRef(0)
  const websocketRef = useRef(null)
  const selectedIpRef = useRef(null)
  const appModeRef = useRef('live')
  const activeSourceRef = useRef('live')
  const activeFilterRef = useRef({ raw: '', type: 'all' })
  const filteredPacketsRef = useRef([])
  const showLabelsRef = useRef(true)
  const labelModeRef = useRef('resolvedIp')
  const cameraZoomRef = useRef(DEFAULT_CAMERA_ZOOM)
  const hostnamesRef = useRef(new Map())
  const macNamesRef = useRef(new Map())
  const cameraRef = useRef(null)
  const pointTargetRef = useRef({ active: false, ip: null, x: 0, y: 0 })
  const pointerLockedIpRef = useRef(null)
  const layoutSpreadRef = useRef({ value: 1, target: 1 })
  const ingestPacketRef = useRef(null)
  const resetGraphRef = useRef(null)
  const snapshotGraphRef = useRef(null)
  const rebuildGraphRef = useRef(null)
  const lastIngestedReplayIndexRef = useRef(0)
  const replayIndexRef = useRef(0)
  const replayPacketsRef = useRef([])

  const [gesturesEnabled, setGesturesEnabled] = useState(false)
  const gestureCleanupRef = useRef(null)
  const [pointReticle, setPointReticle] = useState({
    active: false,
    locked: false,
    x: 50,
    y: 50,
    lockKind: null,
    lockProgress: 0,
    mode: 'zoom',
  })

  const applyOrbitRef = useRef(() => { })
  const screensaverActiveRef = useRef(false)
  const [screensaverActive, setScreensaverActive] = useState(false)
  const screensaverRef = useRef({ timer: null, spinAngle: 0 })
  const [activeTab, setActiveTab] = useState('live')
  const [appMode, setAppMode] = useState('live')
  const [activeSource, setActiveSource] = useState('live')
  const [filterInput, setFilterInput] = useState('')
  const [activeFilter, setActiveFilter] = useState({ raw: '', type: 'all' })
  const [filterError, setFilterError] = useState('')
  const [filterSuggestions, setFilterSuggestions] = useState([])
  const [suggestionIndex, setSuggestionIndex] = useState(-1)
  const [cameraZoom, setCameraZoom] = useState(DEFAULT_CAMERA_ZOOM)
  const [showLabels, setShowLabels] = useState(true)
  const [labelMode, setLabelMode] = useState('resolvedIp')
  const [status, setStatus] = useState('connecting')
  const [captureInterface, setCaptureInterface] = useState('en0')
  const [selectedIp, setSelectedIp] = useState(null)
  const [selectedPacketId, setSelectedPacketId] = useState(null)
  const conversationSort = 'bytes'
  const [replayPackets, setReplayPackets] = useState([])
  const [livePackets, setLivePackets] = useState([])
  const [replayMeta, setReplayMeta] = useState(null)
  const [replayState, setReplayState] = useState('idle')
  const [replayIndex, setReplayIndex] = useState(0)
  const [replayTime, setReplayTime] = useState(0)
  const [replaySpeed, setReplaySpeed] = useState(1)
  const [replayError, setReplayError] = useState('')
  const [analysisSnapshot, setAnalysisSnapshot] = useState(() => createEmptyAnalysis())
  const analysisSnapshotTimerRef = useRef(null)
  const graphRebuildTimerRef = useRef(null)

  // Feature 4 — protocol toggles
  const [activeProtocols, setActiveProtocols] = useState(() => new Set(['TCP','UDP','DNS','ARP','BCAST','MCAST','OTHER']))

  // Feature 2 — inspection drawer
  const [drawerTab, setDrawerTab] = useState('overview')

  // Feature 8 — hover / pinned labels
  const hoveredIpRef = useRef(null)
  const pinnedIpsRef = useRef(new Set())

  // Feature 7 — alerts
  const alertsRef = useRef([])
  const seenIpsRef = useRef(new Set())

  // Feature 6 — DNS zone tracking
  const dnsServerIpsRef = useRef(new Set())

  // ── Phase 1: Checkpoint + Diff system ──────────────────────

  const [checkpoints, setCheckpoints] = useState(() => {
    try { return JSON.parse(localStorage.getItem('pacmap_checkpoints') || '[]') }
    catch { return [] }
  })
  const [checkpointPanelOpen, setCheckpointPanelOpen] = useState(false)
  const [activeDiff, setActiveDiff] = useState(null)

  // Checkpoint label UI state
  const [pendingLabel, setPendingLabel] = useState('')
  const [labelingOpen, setLabelingOpen] = useState(false)
  const [editingCpId, setEditingCpId] = useState(null)
  const [editingCpLabel, setEditingCpLabel] = useState('')

  // Auto-checkpoint mode
  const [autoCheckpointMode, setAutoCheckpointMode] = useState('off')
  const autoCheckpointModeRef = useRef('off')

  // Live change feed
  const [changeFeed, setChangeFeed] = useState([])
  const [feedOpen, setFeedOpen] = useState(false)
  const feedQueueRef = useRef([])
  const pushFeedEventRef = useRef(null)

  // activeDiff shape: { baseId: string|'current', compareId: string|'current', result: DiffResult } | null
  const [diffMode, setDiffMode] = useState(false)  // "Diff Only" toggle
  const [diffReasonTooltip, setDiffReasonTooltip] = useState(null) // { ip, x, y, text } | null
  const [rightPanelOpen, setRightPanelOpen] = useState(true)

  // Path trace: activates when filter contains both ip.src and ip.dst
  const [pathTrace, setPathTrace] = useState(null)
  const pathTraceRef = useRef(null)
  const [liveAnalysisCollapsed, setLiveAnalysisCollapsed] = useState(false)

  // Reference Snapshot — pointer to one checkpoint ID, persisted
  const [referenceId, setReferenceId] = useState(() =>
    localStorage.getItem('pacmap_reference_id') || null
  )

  // Traffic De-emphasis — view-layer-only opacity reduction for BCAST/MCAST
  const [deemphasizeGroups, setDeemphasizeGroups] = useState(new Set())
  const deemphasizeGroupsRef = useRef(new Set())

  // ── Time Window ──────────────────────────────────────────────
  // null = full data; replay: relative seconds (0–duration); live: absolute unix seconds
  const [liveTime, setLiveTime] = useState(null)   // null = live edge; live mode history scrubber
  const liveTimeRef = useRef(null)
  const windowDiffResultRef = useRef(null)
  const [timeRange, setTimeRange] = useState(null)
  const timeRangeRef = useRef(null) // sync for WebSocket closure gating
  const [windowCompareActive, setWindowCompareActive] = useState(false)
  const windowRebuildTimerRef = useRef(null)
  const trackRef = useRef(null)
  const dragStateRef = useRef({
    mode: null,  // 'playhead' | 'windowLeft' | 'windowRight' | 'windowBody' | 'drawing' | 'playheadOrDraw'
    startTime: 0,
    startWindowStart: 0,
    startWindowEnd: 0,
    movedEnough: false,
  })

  // Bridge refs — assigned inside Three.js useEffect closure (where nodeStore/edgeStore live)
  const applyDiffStateRef = useRef(null)
  const clearDiffStateRef = useRef(null)
  const queueAutoCheckpointRef = useRef(null)
  const activeDiffRef = useRef(null)
  const setDiffReasonTooltipRef = useRef(setDiffReasonTooltip)

  // Auto-checkpoint accumulation
  const autoCheckpointQueueRef = useRef([])
  const autoCheckpointTimerRef = useRef(null)
  // Track external connections seen to avoid re-triggering auto-checkpoint for known edges
  const seenExternalEdgesRef = useRef(new Set())
  // Per-frame spike detection counter
  const frameCountRef = useRef(0)
  const diffModeRef = useRef(false)

  // Persist checkpoints to localStorage
  useEffect(() => {
    localStorage.setItem('pacmap_checkpoints', JSON.stringify(checkpoints.slice(-50)))
  }, [checkpoints])

  // Persist reference ID to localStorage
  useEffect(() => {
    if (referenceId) localStorage.setItem('pacmap_reference_id', referenceId)
    else localStorage.removeItem('pacmap_reference_id')
  }, [referenceId])

  // Sync deemphasizeGroups to ref for Three.js animation loop
  useEffect(() => {
    deemphasizeGroupsRef.current = deemphasizeGroups
  }, [deemphasizeGroups])

  // Sync pathTrace to ref for Three.js animation loop
  useEffect(() => { pathTraceRef.current = pathTrace }, [pathTrace])

  const sourcePackets = useMemo(() => {
    if (activeSource === 'replay') return replayPackets.slice(Math.max(0, replayIndex - ANALYSIS_PACKET_WINDOW), replayIndex)
    return livePackets.slice(-ANALYSIS_PACKET_WINDOW)
  }, [activeSource, livePackets, replayIndex, replayPackets])

  const filteredPackets = useMemo(() => {
    return sourcePackets.filter((packet) => {
      const group = packetProtocolGroup(packet)
      if (!activeProtocols.has(group)) return false
      return packetMatchesFilter(packet, activeFilter)
    })
  }, [activeFilter, sourcePackets, activeProtocols])

  // All packets available regardless of replay-index window (for time-range filtering)
  const allAvailablePackets = activeSource === 'replay' ? replayPackets : livePackets

  // Path trace: BFS over full captured graph when filter contains both ip.src and ip.dst.
  // Uses allAvailablePackets (not filteredPackets) so intermediate hops not excluded by the IP filter.
  useEffect(() => {
    const endpoints = extractPathEndpoints(activeFilter)
    if (!endpoints) {
      setPathTrace(null)
      return
    }
    const { src, dst } = endpoints
    const pkts = activeSource === 'replay' ? replayPackets : livePackets

    const adjacency = new Map()
    const edgeStats = new Map()
    for (const pkt of pkts) {
      const a = pkt.srcIp || pkt.src
      const b = pkt.dstIp || pkt.dst
      if (!a || !b || a === b) continue
      if (!adjacency.has(a)) adjacency.set(a, new Set())
      if (!adjacency.has(b)) adjacency.set(b, new Set())
      adjacency.get(a).add(b)
      adjacency.get(b).add(a)
      const key = edgeKey(a, b)
      if (!edgeStats.has(key)) edgeStats.set(key, { packets: 0, bytes: 0 })
      const s = edgeStats.get(key)
      s.packets++
      s.bytes += pkt.size || 0
    }

    const pathIps = bfsPath(src, dst, adjacency)
    if (!pathIps) {
      setPathTrace({ src, dst, found: false, hops: [], pathIps: [], pathEdgeKeys: new Set() })
      return
    }

    const hops = []
    const pathEdgeKeys = new Set()
    for (let i = 0; i < pathIps.length - 1; i++) {
      const a = pathIps[i], b = pathIps[i + 1]
      const key = edgeKey(a, b)
      pathEdgeKeys.add(key)
      const s = edgeStats.get(key) ?? { packets: 0, bytes: 0 }
      hops.push({ src: a, dst: b, packets: s.packets, bytes: s.bytes })
    }
    setPathTrace({ src, dst, found: true, hops, pathIps, pathEdgeKeys })
  }, [activeFilter, activeSource, livePackets, replayPackets])

  // Coordinate bounds for the timeline range slider
  const timelineBounds = useMemo(() => {
    if (activeSource === 'replay' && replayMeta) return { min: 0, max: replayMeta.duration }
    if (livePackets.length > 1) {
      let min = Infinity, max = -Infinity
      livePackets.forEach(p => { if (p.timestamp < min) min = p.timestamp; if (p.timestamp > max) max = p.timestamp })
      return min < max ? { min, max } : null
    }
    return null
  }, [activeSource, replayMeta, livePackets])

  // Active scrubber position: clamped to window if one exists
  const activeScrubberTime = useMemo(() => {
    const raw = activeSource === 'replay'
      ? replayTime
      : (liveTime ?? timelineBounds?.max ?? null)
    if (raw === null) return null
    if (timeRange) return Math.max(timeRange.start, Math.min(timeRange.end, raw))
    return raw
  }, [activeSource, replayTime, liveTime, timeRange, timelineBounds])

  // Packets filtered to the selected time window (+ protocol + text filter)
  const windowPackets = useMemo(() => {
    if (!timeRange || activeScrubberTime === null) return null
    return allAvailablePackets.filter(p => {
      const t = activeSource === 'replay' ? p.replayTime : p.timestamp
      if (t < timeRange.start || t > activeScrubberTime) return false
      const group = packetProtocolGroup(p)
      if (!activeProtocols.has(group)) return false
      return packetMatchesFilter(p, activeFilter)
    })
  }, [timeRange, allAvailablePackets, activeSource, activeProtocols, activeFilter, activeScrubberTime, timelineBounds])

  // Baseline: all packets before the window opened (empty base = all window packets are "new")
  const baseWindowPackets = useMemo(() => {
    if (!timeRange) return null
    return allAvailablePackets.filter(p => {
      const t = activeSource === 'replay' ? p.replayTime : p.timestamp
      return t < timeRange.start
    })
  }, [timeRange, allAvailablePackets, activeSource])

  const hasBaseWindow = Boolean(timeRange && windowPackets?.length)

  // Window diff (only computed when compare is active)
  const windowDiffResult = useMemo(() => {
    if (!timeRange || !windowPackets || !windowCompareActive) return null
    return computeCheckpointDiff(
      buildWindowSnapshot(baseWindowPackets ?? []),
      buildWindowSnapshot(windowPackets)
    )
  }, [timeRange, windowPackets, baseWindowPackets, windowCompareActive])

  // Traffic analysis for the selected window (for summary panel)
  const windowAnalysis = useMemo(() => {
    if (!timeRange || !windowPackets) return null
    return buildTrafficAnalysis(windowPackets, null, 'bytes')
  }, [timeRange, windowPackets])

  const selectedPacket = useMemo(
    () => filteredPackets.find((packet) => packet.id === selectedPacketId) || null,
    [filteredPackets, selectedPacketId],
  )

  const trafficAnalysis = analysisSnapshot

  useEffect(() => {
    selectedIpRef.current = selectedIp
    if (!selectedIp) pointerLockedIpRef.current = null
    pointTargetRef.current = selectedIp
      ? { active: true, ip: selectedIp, x: 0, y: 0 }
      : { active: false, ip: null, x: 0, y: 0 }
  }, [selectedIp])

  useEffect(() => {
    appModeRef.current = appMode
  }, [appMode])

  useEffect(() => {
    activeSourceRef.current = activeSource
  }, [activeSource])

  useEffect(() => {
    activeFilterRef.current = activeFilter
  }, [activeFilter])

  useEffect(() => {
    filteredPacketsRef.current = filteredPackets
  }, [filteredPackets])

  useEffect(() => { replayIndexRef.current = replayIndex }, [replayIndex])
  useEffect(() => { replayPacketsRef.current = replayPackets }, [replayPackets])
  useEffect(() => { timeRangeRef.current = timeRange }, [timeRange])
  useEffect(() => { liveTimeRef.current = liveTime }, [liveTime])
  useEffect(() => { windowDiffResultRef.current = windowDiffResult }, [windowDiffResult])

  // Graph rebuild when time window changes
  useEffect(() => {
    if (!rebuildGraphRef.current) return
    if (windowRebuildTimerRef.current) clearTimeout(windowRebuildTimerRef.current)

    if (timeRange !== null && windowPackets !== null) {
      // When replay is actively playing, the existing ingest loop handles graph updates.
      // Only rebuild on pause/scrub/end to avoid fighting the incremental ingest.
      if (activeSource === 'replay' && replayState === 'playing') return
      windowRebuildTimerRef.current = setTimeout(() => {
        windowRebuildTimerRef.current = null
        rebuildGraphRef.current?.(windowPackets)
      }, 150)
    } else if (timeRange === null) {
      rebuildGraphRef.current(filteredPacketsRef.current)
    }

    return () => { if (windowRebuildTimerRef.current) clearTimeout(windowRebuildTimerRef.current) }
  }, [timeRange, windowPackets, activeSource, replayState])

  // Live mode history scrubber — rebuild graph frozen at liveTime (or return to live edge)
  useEffect(() => {
    if (activeSource !== 'live' || timeRange !== null || !rebuildGraphRef.current) return
    if (windowRebuildTimerRef.current) clearTimeout(windowRebuildTimerRef.current)

    if (liveTime !== null) {
      const packets = livePacketsRef.current.filter(p => {
        if (p.timestamp > liveTime) return false
        const group = packetProtocolGroup(p)
        if (!activeProtocols.has(group)) return false
        return packetMatchesFilter(p, activeFilterRef.current)
      })
      windowRebuildTimerRef.current = setTimeout(() => {
        windowRebuildTimerRef.current = null
        rebuildGraphRef.current?.(packets)
      }, 150)
    } else {
      rebuildGraphRef.current(filteredPacketsRef.current)
    }
    return () => { if (windowRebuildTimerRef.current) clearTimeout(windowRebuildTimerRef.current) }
  }, [liveTime, activeSource, activeFilter, activeProtocols, timeRange])

  // Apply/clear diff visuals when window compare result changes
  useEffect(() => {
    if (!applyDiffStateRef.current || !clearDiffStateRef.current) return
    if (windowDiffResult && windowCompareActive) {
      applyDiffStateRef.current(windowDiffResult)
    } else {
      clearDiffStateRef.current()
    }
  }, [windowDiffResult, windowCompareActive])

  // Clear window state when source switches
  useEffect(() => {
    setTimeRange(null)
    setWindowCompareActive(false)
    setLiveTime(null)
    setActiveDiff(null)
    setReferenceId(null)
  }, [activeSource])

  useEffect(() => {
    if (analysisSnapshotTimerRef.current !== null) return undefined

    analysisSnapshotTimerRef.current = window.setTimeout(() => {
      analysisSnapshotTimerRef.current = null
      setAnalysisSnapshot(buildTrafficAnalysis(filteredPacketsRef.current, replayMeta, conversationSort))
    }, ANALYSIS_SNAPSHOT_MS)

    return () => {
      if (analysisSnapshotTimerRef.current !== null) {
        clearTimeout(analysisSnapshotTimerRef.current)
        analysisSnapshotTimerRef.current = null
      }
    }
  }, [conversationSort, filteredPackets, replayMeta])

  // Keep refs pointing at latest values so Three.js loop doesn't get stale closures
  useEffect(() => {
    queueAutoCheckpointRef.current = queueAutoCheckpoint
    pushFeedEventRef.current = (event) => {
      feedQueueRef.current.push({ ...event, id: crypto.randomUUID(), ts: Date.now() })
    }
  })
  useEffect(() => {
    diffModeRef.current = diffMode
  }, [diffMode])
  useEffect(() => {
    autoCheckpointModeRef.current = autoCheckpointMode
  }, [autoCheckpointMode])
  // Flush feed queue to state every 500ms (batch updates from Three.js closure)
  useEffect(() => {
    const interval = setInterval(() => {
      if (feedQueueRef.current.length === 0) return
      const events = feedQueueRef.current.splice(0)
      setChangeFeed(prev => [...events, ...prev].slice(0, 50))
    }, 500)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    activeDiffRef.current = activeDiff
    setDiffReasonTooltipRef.current = setDiffReasonTooltip
  }, [activeDiff])

  // Keep "vs Current" diff live in live mode: re-diff whenever the graph state changes
  useEffect(() => {
    const ad = activeDiffRef.current
    if (!ad || ad.compareId !== 'current' || activeSource !== 'live') return
    const base = checkpoints.find(c => c.id === ad.baseId) || null
    const compare = buildCurrentState()
    if (!base || !compare) return
    const result = computeCheckpointDiff(base, compare)
    setActiveDiff(prev => prev ? { ...prev, result } : null)
    applyDiffStateRef.current?.(result)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisSnapshot, activeSource])

  useEffect(() => {
    showLabelsRef.current = showLabels
  }, [showLabels])

  useEffect(() => {
    labelModeRef.current = labelMode
    setShowLabels(labelMode !== 'off')
  }, [labelMode])

  useEffect(() => {
    hostnamesRef.current = trafficAnalysis.hostnames
    macNamesRef.current = trafficAnalysis.macNames
  }, [trafficAnalysis.hostnames, trafficAnalysis.macNames])

  useEffect(() => {
    if (!cameraRef.current) return
    cameraZoomRef.current = cameraZoom
    cameraRef.current.zoom = cameraZoom
    cameraRef.current.updateProjectionMatrix()
  }, [cameraZoom])

  useEffect(() => {
    function resetTimer() {
      if (screensaverRef.current.timer) clearTimeout(screensaverRef.current.timer)
      if (screensaverActiveRef.current) {
        screensaverActiveRef.current = false
        setScreensaverActive(false)
        screensaverRef.current.initialized = false
      }
      screensaverRef.current.timer = setTimeout(() => {
        screensaverActiveRef.current = true
        setScreensaverActive(true)
        setActiveTab('live')
      }, 60000)
    }

    const events = ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart', 'pointermove']
    events.forEach(e => window.addEventListener(e, resetTimer, { passive: true }))
    resetTimer()

    return () => {
      events.forEach(e => window.removeEventListener(e, resetTimer))
      if (screensaverRef.current.timer) clearTimeout(screensaverRef.current.timer)
    }
  }, [])

  useEffect(() => {
    const mount = mountRef.current
    const nodeStore = nodesRef.current
    const edgeStore = edgesRef.current
    const packetStore = packetsRef.current
    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x050505)

    const camera = new THREE.PerspectiveCamera(55, mount.clientWidth / mount.clientHeight, 1, 4000)
    camera.position.set(0, 620, 520)
    cameraRef.current = camera

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.outputColorSpace = THREE.SRGBColorSpace
    mount.appendChild(renderer.domElement)

    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.dampingFactor = 0.08
    controls.screenSpacePanning = true
    controls.minDistance = 200
    controls.maxDistance = 2200
    controls.mouseButtons = {
      LEFT: THREE.MOUSE.ROTATE,
      MIDDLE: THREE.MOUSE.PAN,
      RIGHT: THREE.MOUSE.PAN,
    }
    controls.touches = {
      ONE: THREE.TOUCH.ROTATE,
      TWO: THREE.TOUCH.DOLLY_PAN,
    }
    controls.minPolarAngle = 0
    controls.maxPolarAngle = Math.PI

    // Pan reset fix: skip updateOrbitTarget() while user is actively controlling camera,
    // and permanently once they have intentionally panned.
    let orbitActive = false
    let orbitActiveCooldown = null
    let userHasPanned = false       // set true on first deliberate pan; reset on clearGraph
    let targetBeforeGesture = null  // snapshot of controls.target at gesture start

    controls.addEventListener('start', () => {
      orbitActive = true
      targetBeforeGesture = controls.target.clone()
      if (orbitActiveCooldown) clearTimeout(orbitActiveCooldown)
    })
    controls.addEventListener('end', () => {
      if (orbitActiveCooldown) clearTimeout(orbitActiveCooldown)
      // Detect pan: if the orbit target moved horizontally, the user panned (not just rotated/zoomed)
      if (targetBeforeGesture) {
        const dx = Math.abs(controls.target.x - targetBeforeGesture.x)
        const dz = Math.abs(controls.target.z - targetBeforeGesture.z)
        if (dx > 1 || dz > 1) userHasPanned = true
        targetBeforeGesture = null
      }
      orbitActiveCooldown = setTimeout(() => {
        orbitActive = false
        orbitActiveCooldown = null
      }, 500)
    })

    scene.add(new THREE.HemisphereLight(0xffffff, 0x161616, 2.9))
    scene.add(new THREE.AmbientLight(0xffffff, 1.55))
    const keyLight = new THREE.DirectionalLight(0xffffff, 2.1)
    keyLight.position.set(220, 260, 160)
    scene.add(keyLight)
    const rimLight = new THREE.PointLight(0xd8d8dc, 1.8, 600)
    rimLight.position.set(-180, -80, -120)
    scene.add(rimLight)

    const nodeGeometry = new THREE.SphereGeometry(8, 20, 14)
    const packetGeometry = new THREE.SphereGeometry(1.4, 10, 10)
    const raycaster = new THREE.Raycaster()

    // Scratch objects for ring billboarding — reused every frame, zero allocations
    const _spinQ = new THREE.Quaternion()
    const _zAxis = new THREE.Vector3(0, 0, 1)
    const pointer = new THREE.Vector2()

    function updateOrbitTarget() {
      let count = 0
      const center = new THREE.Vector3()
      nodeStore.forEach((node) => {
        if (!node.group.visible) return
        center.x += node.x
        center.y += node.y
        center.z += node.z
        count += 1
      })
      if (count) {
        center.multiplyScalar(1 / count)
        controls.target.lerp(center, 0.06)
      }
    }

    function snapshotState() {
      // Keep this hook available for summary packets without forcing React renders on the graph hot path.
    }

    function rebuildGraph(packets) {
      // When path tracing is active, render only the hop packets so intermediate
      // nodes exist in the scene and can be highlighted cyan.
      const pt = pathTraceRef.current
      if (pt?.found) {
        const allPkts = activeSourceRef.current === 'replay' ? replayPacketsRef.current : livePacketsRef.current
        const pathEdgeKeySet = pt.pathEdgeKeys
        packets = allPkts.filter(pkt => {
          const a = pkt.srcIp || pkt.src
          const b = pkt.dstIp || pkt.dst
          if (!a || !b) return false
          return pathEdgeKeySet.has(edgeKey(a, b))
        })
      }

      // Preserve settled positions so layout doesn't shock on window/filter updates
      const savedPositions = new Map()
      nodeStore.forEach((node, ip) => {
        savedPositions.set(ip, {
          x: node.x, y: node.y, z: node.z,
          vx: node.vx, vy: node.vy, vz: node.vz,
        })
      })

      clearGraph(true)
      packets.forEach((packet) => ingestPacket(packet))

      // Restore positions for nodes that survived the rebuild; new nodes keep randomPosition
      nodeStore.forEach((node, ip) => {
        const pos = savedPositions.get(ip)
        if (!pos) return
        node.x = pos.x; node.y = pos.y; node.z = pos.z
        node.vx = pos.vx; node.vy = pos.vy; node.vz = pos.vz
        node.tx = pos.x; node.ty = pos.y; node.tz = pos.z
        node.group.position.set(pos.x, pos.y, pos.z)
      })

      snapshotState()
      if (applyDiffStateRef.current && windowDiffResultRef.current) {
        applyDiffStateRef.current(windowDiffResultRef.current)
      }
    }

    function labelForNode(node) {
      const mode = labelModeRef.current
      if (mode === 'off') return ''
      if (mode === 'rawMac') return node.mac || node.ip
      if (mode === 'resolvedMac') return macNamesRef.current.get(node.mac) || node.mac || node.ip
      if (mode === 'resolvedIp') return hostnamesRef.current.get(node.ip) || node.ip
      return node.ip
    }

    function refreshNodeLabel(node) {
      const nextLabel = labelForNode(node)
      if (node.labelText === nextLabel) return
      node.labelText = nextLabel
      updateTextSprite(node.label, nextLabel || node.ip)
    }

    function clearGraph(soft = false) {
      packetStore.splice(0).forEach((packet) => {
        scene.remove(packet.mesh)
        packet.mesh.material.dispose()
      })

      edgeStore.forEach((edge) => {
        scene.remove(edge.mesh)
        edge.mesh.geometry.dispose()
        edge.mesh.material.dispose()
      })
      edgeStore.clear()

      nodeStore.forEach((node) => {
        scene.remove(node.group)
        node.mesh.material.dispose()
        node.label.material.map.dispose()
        node.label.material.dispose()
        node.ring.geometry.dispose()
        node.ring.material.dispose()
      })
      nodeStore.clear()
      setSelectedIp(null)
      pointTargetRef.current = { active: false, ip: null, x: 0, y: 0 }
      setPointReticle((current) => ({ ...current, active: false, locked: false }))

      if (!soft) {
        controls.target.set(0, 0, 0)
        controls.update()
        userHasPanned = false
        layoutSpreadRef.current.value = 1
        layoutSpreadRef.current.target = 1
      }
    }

    function ensureNode(ip) {
      if (nodeStore.has(ip)) return nodeStore.get(ip)

      const index = nodeStore.size
      const position = randomPosition(index)
      const group = new THREE.Group()
      group.position.set(position.x, position.y, position.z)

      const material = new THREE.MeshStandardMaterial({
        color: 0xe7e7ea,
        emissive: 0x9b9ba3,
        emissiveIntensity: 0.28,
        roughness: 0.42,
        metalness: 0.22,
        transparent: true,
        opacity: 0.96,
      })
      const mesh = new THREE.Mesh(nodeGeometry, material)
      mesh.userData.ip = ip
      group.add(mesh)

      const label = makeTextSprite(ip)
      label.position.set(0, 19, 0)
      group.add(label)

      const ringGeo = new THREE.TorusGeometry(12, 1.2, 6, 32)
      const ringMat = new THREE.MeshBasicMaterial({ color: 0x60a5fa, transparent: true, opacity: 0 })
      const ring = new THREE.Mesh(ringGeo, ringMat)
      group.add(ring)

      scene.add(group)

      const node = {
        ip,
        group,
        mesh,
        label,
        ring,
        x: position.x,
        y: position.y,
        z: position.z,
        tx: position.x,
        ty: position.y,
        tz: position.z,
        vx: 0,
        vy: 0,
        vz: 0,
        bytes: 0,
        packets: 0,
        recentBytes: 0,
        renderScale: 1,
        clusterAnchor: clusterAnchor(ip, dnsServerIpsRef.current),
        mac: '',
        labelText: ip,
        ringSpinAngle: 0,
      }

      nodeStore.set(ip, node)
      return node
    }

    function ensureEdge(src, dst) {
      const key = edgeKey(src, dst)
      if (edgeStore.has(key)) return edgeStore.get(key)

      const geometry = new THREE.BufferGeometry()
      geometry.setAttribute('position', new THREE.BufferAttribute(new Float32Array(6), 3))

      const material = new THREE.LineBasicMaterial({
        color: 0xf2f2f5,
        transparent: true,
        opacity: 0.58,
        depthTest: true,
      })
      const mesh = new THREE.Line(geometry, material)
      scene.add(mesh)

      const edge = { key, src, dst, mesh, bytes: 0, packets: 0, recentBytes: 0, recentPackets: 0 }
      edgeStore.set(key, edge)
      return edge
    }

    function buildAdjacency() {
      const adjacency = new Map()

      edgeStore.forEach((edge) => {
        if (!adjacency.has(edge.src)) adjacency.set(edge.src, new Set())
        if (!adjacency.has(edge.dst)) adjacency.set(edge.dst, new Set())
        adjacency.get(edge.src).add(edge.dst)
        adjacency.get(edge.dst).add(edge.src)
      })

      return adjacency
    }

    function focusDepths(selected) {
      const depths = new Map()
      if (!selected || !nodeStore.has(selected)) return depths

      const adjacency = buildAdjacency()
      depths.set(selected, 0)

        ;[...(adjacency.get(selected) || [])].forEach((ip) => {
          depths.set(ip, 1)
        })

      return depths
    }

    function applyGraphForces() {
      const nodeList = [...nodeStore.values()]
      const edgeList = [...edgeStore.values()]
      const adjacency = buildAdjacency()
      const spread = layoutSpreadRef.current.value
      const spreadForce = Math.pow(spread, 1.18)
      const pointTarget = pointTargetRef.current
      const depths = pointTarget.active && pointTarget.ip ? focusDepths(pointTarget.ip) : new Map()
      const hasFocus = depths.size > 0
      const visibleNodes = nodeList.filter((node) => (adjacency.get(node.ip)?.size || 0) > 0)

      nodeList.forEach((node) => {
        const degree = adjacency.get(node.ip)?.size || 0
        node.group.visible = degree > 0
        node.renderScale = 1
        if (!node.group.visible) return

        const centerPull = 0.0028 / Math.max(spreadForce, 0.78)
        const clusterPull = 0.0018
        const anchor = node.clusterAnchor || { x: 0, y: 0, z: 0 }

        node.vx += -node.x * centerPull + (anchor.x * spreadForce - node.x) * clusterPull
        node.vy += -node.y * centerPull + (anchor.y * spreadForce - node.y) * clusterPull
        node.vz += -node.z * centerPull + (anchor.z * spreadForce - node.z) * clusterPull
      })

      for (let i = 0; i < visibleNodes.length; i += 1) {
        for (let j = i + 1; j < visibleNodes.length; j += 1) {
          const a = visibleNodes[i]
          const b = visibleNodes[j]

          const dx = b.x - a.x
          const dy = b.y - a.y
          const dz = b.z - a.z
          const distanceSq = Math.max(dx * dx + dy * dy + dz * dz, 0.01)
          const distance = Math.sqrt(distanceSq)
          const spacing = collisionNodeRadius(a) * 10 + collisionNodeRadius(b) * 10 + 34 + 58 * spreadForce
          const repel = Math.min((spacing * spacing) / distanceSq, 4.4) * 0.072 * spreadForce
          const nx = dx / distance
          const ny = dy / distance
          const nz = dz / distance

          a.vx -= nx * repel
          a.vy -= ny * repel
          a.vz -= nz * repel
          b.vx += nx * repel
          b.vy += ny * repel
          b.vz += nz * repel
        }
      }

      edgeList.forEach((edge) => {
        const a = nodeStore.get(edge.src)
        const b = nodeStore.get(edge.dst)
        if (!a || !b) return
        edge.mesh.visible = a.group.visible && b.group.visible
        if (!edge.mesh.visible) return

        const dx = b.x - a.x
        const dy = b.y - a.y
        const dz = b.z - a.z
        const distance = Math.max(Math.sqrt(dx * dx + dy * dy + dz * dz), 0.01)
        const desired = THREE.MathUtils.clamp(72 + Math.log10(edge.bytes + 1) * 11, 72, 155) * spreadForce
        const strength = THREE.MathUtils.clamp(0.004 + Math.log10(edge.packets + 1) * 0.0022, 0.004, 0.018)
        const force = (distance - desired) * strength
        const nx = dx / distance
        const ny = dy / distance
        const nz = dz / distance

        a.vx += nx * force
        a.vy += ny * force
        a.vz += nz * force
        b.vx -= nx * force
        b.vy -= ny * force
        b.vz -= nz * force
      })

      for (let i = 0; i < visibleNodes.length; i += 1) {
        for (let j = i + 1; j < visibleNodes.length; j += 1) {
          const a = visibleNodes[i]
          const b = visibleNodes[j]

          const minDistance = collisionNodeRadius(a) + collisionNodeRadius(b) + 18 + 28 * spreadForce
          const dx = b.x - a.x
          const dy = b.y - a.y
          const dz = b.z - a.z
          const distance = Math.max(Math.sqrt(dx * dx + dy * dy + dz * dz), 0.01)
          if (distance >= minDistance) continue

          const push = (minDistance - distance) * 0.5
          const nx = dx / distance
          const ny = dy / distance
          const nz = dz / distance

          a.x -= nx * push
          a.y -= ny * push
          a.z -= nz * push
          b.x += nx * push
          b.y += ny * push
          b.z += nz * push
        }
      }

      visibleNodes.forEach((node) => {
        if (!node.group.visible) return
        node.vx *= 0.84
        node.vy *= 0.84
        node.vz *= 0.84
        node.x += THREE.MathUtils.clamp(node.vx, -5.8, 5.8)
        node.y += THREE.MathUtils.clamp(node.vy, -5.8, 5.8)
        node.z += THREE.MathUtils.clamp(node.vz, -5.8, 5.8)
      })

      return { hasFocus, depths }
    }

    function spawnPacket(src, dst, proto, size) {
      if (packetStore.length >= MAX_PACKET_PARTICLES) return

      const protocol = PROTOCOLS[proto] || PROTOCOLS.OTHER
      const material = new THREE.MeshBasicMaterial({
        color: protocol.color,
        transparent: true,
        opacity: 0.96,
      })
      const mesh = new THREE.Mesh(packetGeometry, material)
      const scale = THREE.MathUtils.clamp(0.75 + size / 1800, 0.75, 1.9)
      mesh.scale.setScalar(scale)
      scene.add(mesh)

      packetStore.push({
        mesh,
        src,
        dst,
        progress: 0,
        speed: 0.012 + Math.random() * 0.016,
      })
    }

    function ingestPacket(packet) {
      const src = packet.src
      const dst = packet.dst
      if (!src || !dst || src === dst) return

      const size = Number(packet.size) || 0
      const proto = packet.proto || 'OTHER'

      // Feature 6 — track DNS servers (responses come FROM port 53)
      if (proto === 'DNS' && (Number(packet.srcPort) === 53)) {
        dnsServerIpsRef.current.add(src)
      }

      const srcNode = ensureNode(src)
      const dstNode = ensureNode(dst)

      // Feature 7 — new host alerts + auto-checkpoint
      if (!seenIpsRef.current.has(src)) {
        seenIpsRef.current.add(src)
        alertsRef.current.push({ type: 'newHost', ip: src, ts: Date.now(), label: 'New Host' })
        if (alertsRef.current.length > 20) alertsRef.current.shift()
        const kind = classifyIp(src)
        if (kind !== 'multicast' && kind !== 'broadcast' && kind !== 'loopback') {
          queueAutoCheckpointRef.current?.('New host discovered')
          pushFeedEventRef.current?.({ type: 'new-host', ip: src, reason: `New host: ${src}`, severity: 'info' })
        }
      }
      if (!seenIpsRef.current.has(dst)) {
        seenIpsRef.current.add(dst)
        alertsRef.current.push({ type: 'newHost', ip: dst, ts: Date.now(), label: 'New Host' })
        if (alertsRef.current.length > 20) alertsRef.current.shift()
        const kind = classifyIp(dst)
        if (kind !== 'multicast' && kind !== 'broadcast' && kind !== 'loopback') {
          queueAutoCheckpointRef.current?.('New host discovered')
          pushFeedEventRef.current?.({ type: 'new-host', ip: dst, reason: `New host: ${dst}`, severity: 'info' })
        }
      }
      const edge = ensureEdge(src, dst)

      // Auto-checkpoint: new external connection
      const edgeId = `${src}<->${dst}`
      if (!seenExternalEdgesRef.current.has(edgeId)) {
        const srcKind = classifyIp(src)
        const dstKind = classifyIp(dst)
        if (srcKind === 'external' || dstKind === 'external') {
          seenExternalEdgesRef.current.add(edgeId)
          queueAutoCheckpointRef.current?.('New external connection detected')
          const extIp = srcKind === 'external' ? src : dst
          pushFeedEventRef.current?.({ type: 'external', ip: extIp, reason: `External: ${extIp}`, severity: 'warn' })
        }
      }
      if (packet.srcMac) srcNode.mac = packet.srcMac
      if (packet.dstMac) dstNode.mac = packet.dstMac

      srcNode.bytes += size
      srcNode.packets += 1
      srcNode.recentBytes += size
      dstNode.bytes += size
      dstNode.packets += 1
      dstNode.recentBytes += size
      edge.bytes += size
      edge.packets += 1
      edge.recentBytes += size
      edge.recentPackets += 1

      spawnPacket(src, dst, proto, size)
    }

    function applyNodeSummary(summaryNodes) {
      summaryNodes.forEach((summary) => {
        const node = nodeStore.get(summary.ip)
        if (!node) return
        node.bytes = Math.max(node.bytes, Number(summary.bytes) || 0)
        node.packets = Math.max(node.packets, Number(summary.packets) || 0)
      })
      snapshotState()
    }

    function updateGraphVisuals() {
      const nodeList = [...nodeStore.values()]
      const edgeList = [...edgeStore.values()]
      const { hasFocus, depths } = applyGraphForces()
      const pt = pathTraceRef.current
      const pathActive = pt?.found === true
      const pathIpSet = pathActive ? new Set(pt.pathIps) : null
      const pathEdgeKeys = pathActive ? pt.pathEdgeKeys : null

      nodeList.forEach((node) => {
        const labelsEnabled = showLabelsRef.current
        const depth = hasFocus ? depths.get(node.ip) : 0
        const visibleWeight = hasFocus
          ? { 0: 1, 1: 0.96 }[depth] || 0.14
          : 1
        const zoomOutVisibility = THREE.MathUtils.clamp(
          (DEFAULT_CAMERA_ZOOM - cameraZoomRef.current) / (DEFAULT_CAMERA_ZOOM - MIN_CAMERA_ZOOM),
          0,
          1,
        )
        const labelOpacityFloor = 0.82 + zoomOutVisibility * 0.16
        const scale = (nodeRadius(node) / 8) * nodeRenderScale(node)
        const labelScale = THREE.MathUtils.clamp(nodeRenderScale(node), 0.55, 1)
        const pulse = THREE.MathUtils.clamp(node.recentBytes / 4500, 0, 1.8)
        const t = performance.now() / 1000
        const ds = node.diffState
        const diffScalePulse = ds === 'added'
          ? Math.sin(t * 2.5) * 0.15 + 0.15
          : 0
        refreshNodeLabel(node)
        node.group.position.set(node.x, node.y, node.z)
        node.mesh.scale.lerp(new THREE.Vector3(scale + pulse + diffScalePulse, scale + pulse + diffScalePulse, scale + pulse + diffScalePulse), 0.18)
        node.mesh.material.opacity = THREE.MathUtils.lerp(node.mesh.material.opacity, visibleWeight, 0.12)
        node.label.visible = labelsEnabled
        const maxBytes = Math.max(...[...nodeStore.values()].map(n => n.bytes), 1)
        const importance = Math.log10(node.bytes + 1) / Math.log10(maxBytes + 1)
        const importanceOpacity = THREE.MathUtils.clamp(importance, 0.08, 1)
        const targetLabelOpacity = !labelsEnabled || (hasFocus && depth === undefined)
          ? 0
          : hasFocus
            ? Math.max(visibleWeight, 0.88)
            : importanceOpacity

        node.label.material.opacity = THREE.MathUtils.lerp(
          node.label.material.opacity,
          targetLabelOpacity,
          0.14,
        )
        node.label.position.y = 22 + scale * 7
        node.label.scale.lerp(new THREE.Vector3(150 * labelScale, 38 * labelScale, 1), 0.18)
        node.recentBytes *= 0.91

        // Emissive glow: depth focus first, then diff state overrides
        const emissiveDepth = hasFocus ? depths.get(node.ip) : undefined
        const targetEmissive = emissiveDepth === 0 ? 0.9 : emissiveDepth === 1 ? 0.4 : 0.1
        node.mesh.material.emissiveIntensity = THREE.MathUtils.lerp(node.mesh.material.emissiveIntensity, targetEmissive, 0.1)
        if (emissiveDepth === 0) node.mesh.material.emissive.setHex(0x3b82f6)
        else node.mesh.material.emissive.setHex(0x9b9ba3)

        // Diff visual state — overrides emissive; ring color driven by diff state
        if (ds === 'added') {
          node.mesh.material.emissive.setHex(0x34d399)
          node.mesh.material.emissiveIntensity = THREE.MathUtils.lerp(node.mesh.material.emissiveIntensity, 0.9, 0.12)
        } else if (ds === 'increased') {
          node.mesh.material.emissive.setHex(0xfbbf24)
          node.mesh.material.emissiveIntensity = THREE.MathUtils.lerp(node.mesh.material.emissiveIntensity, 0.65, 0.12)
        } else if (ds === 'decreased') {
          node.mesh.material.emissive.setHex(0xf87171)
          node.mesh.material.emissiveIntensity = THREE.MathUtils.lerp(node.mesh.material.emissiveIntensity, 0.45, 0.12)
        } else if (ds === 'unchanged' && diffModeRef.current) {
          node.mesh.material.opacity = THREE.MathUtils.lerp(node.mesh.material.opacity, 0.06, 0.1)
        }

        // Ring: selection takes priority; diff state drives color/pulse otherwise
        const isSelected = node.ip === selectedIpRef.current
        if (isSelected) {
          if (node.ring.material.color.getHex() !== 0x60a5fa) node.ring.material.color.setHex(0x60a5fa)
          node.ring.material.opacity = THREE.MathUtils.lerp(node.ring.material.opacity, 0.85, 0.1)
          node.ringSpinAngle += 0.012
        } else if (ds === 'added') {
          if (node.ring.material.color.getHex() !== 0x34d399) node.ring.material.color.setHex(0x34d399)
          node.ring.material.opacity = Math.sin(t * 2.5) * 0.28 + 0.62  // 0.34–0.90 pulse
          node.ringSpinAngle += 0.006
        } else if (ds === 'increased') {
          if (node.ring.material.color.getHex() !== 0xfbbf24) node.ring.material.color.setHex(0xfbbf24)
          node.ring.material.opacity = THREE.MathUtils.lerp(node.ring.material.opacity, 0.55, 0.1)
          node.ringSpinAngle += 0.004
        } else if (ds === 'decreased') {
          if (node.ring.material.color.getHex() !== 0xf87171) node.ring.material.color.setHex(0xf87171)
          node.ring.material.opacity = THREE.MathUtils.lerp(node.ring.material.opacity, 0.4, 0.1)
        } else {
          if (node.ring.material.color.getHex() !== 0x60a5fa) node.ring.material.color.setHex(0x60a5fa)
          node.ring.material.opacity = THREE.MathUtils.lerp(node.ring.material.opacity, 0, 0.1)
        }

        // VIEW-LAYER DE-EMPHASIS ONLY — does not affect data, diff, checkpoints, or stats.
        // De-emphasized nodes still participate in all analysis; only their rendering is quieted.
        if (deemphasizeGroupsRef.current.size > 0 && !node.diffState) {
          const nodeKind = classifyIp(node.ip)
          const isDeemphasized =
            (deemphasizeGroupsRef.current.has('BCAST') && (nodeKind === 'broadcast' || isBcastIp(node.ip))) ||
            (deemphasizeGroupsRef.current.has('MCAST') && (nodeKind === 'multicast' || isMcastIp(node.ip)))
          if (isDeemphasized) {
            node.mesh.material.opacity = THREE.MathUtils.lerp(node.mesh.material.opacity, 0.07, 0.1)
          }
        }

        // Path trace — cyan highlight for path nodes, dim everything else
        if (pathActive) {
          if (pathIpSet.has(node.ip)) {
            node.mesh.material.emissive.setHex(0x22d3ee)
            node.mesh.material.emissiveIntensity = 1.0
            node.mesh.material.opacity = 1.0
            node.ring.material.color.setHex(0x22d3ee)
            node.ring.material.opacity = 0.75
          } else {
            node.mesh.material.emissiveIntensity = 0.05
            node.mesh.material.opacity = THREE.MathUtils.lerp(node.mesh.material.opacity, 0.12, 0.1)
            node.ring.material.opacity = 0
          }
        }

        // Phase 1 — Traffic spike detection for auto-checkpoint (sampled every 120 frames)
        frameCountRef.current++
        if (frameCountRef.current % 120 === 0 && node.recentBytes > 0) {
          const avg = node.avgRecentBytes || node.recentBytes
          const aggressive = autoCheckpointModeRef.current === 'aggressive'
          const mult = aggressive ? 3 : 5
          const minBytes = aggressive ? 8000 : 12000
          if (node.recentBytes > avg * mult && node.recentBytes > minBytes) {
            queueAutoCheckpointRef.current?.('Traffic spike detected')
            pushFeedEventRef.current?.({ type: 'spike', ip: node.ip, reason: `Spike: ${node.ip}`, severity: 'warn' })
          }
          node.avgRecentBytes = avg * 0.9 + node.recentBytes * 0.1
        }
      })

      edgeList.forEach((edge) => {
        const a = nodeStore.get(edge.src)
        const b = nodeStore.get(edge.dst)
        if (!a || !b) return

        const srcDepth = hasFocus ? depths.get(edge.src) : 0
        const dstDepth = hasFocus ? depths.get(edge.dst) : 0
        const targetIp = pointTargetRef.current.ip
        const focusedEdge = !hasFocus || (
          srcDepth !== undefined &&
          dstDepth !== undefined &&
          (edge.src === targetIp || edge.dst === targetIp)
        )
        const packetChattyness = THREE.MathUtils.clamp(Math.log1p(edge.recentPackets) / Math.log1p(9), 0, 1)
        const byteChattyness = THREE.MathUtils.clamp(Math.log1p(edge.recentBytes) / Math.log1p(9000), 0, 1)
        const chattyness = THREE.MathUtils.clamp(packetChattyness * 0.68 + byteChattyness * 0.32, 0, 1)
        const maxEdgeBytes = Math.max(...[...edgeStore.values()].map(e => e.bytes), 1)
        const edgeImportance = Math.log10(edge.bytes + 1) / Math.log10(maxEdgeBytes + 1)
        const baseOpacity = focusedEdge ? THREE.MathUtils.clamp(edgeImportance * 0.18, 0.01, 0.18) : 0.02
        const activeOpacity = focusedEdge ? THREE.MathUtils.clamp(edgeImportance * 0.9 + 0.1, 0.1, 0.96) : 0.12
        const targetOpacity = baseOpacity + chattyness * (activeOpacity - baseOpacity)
        const positions = edge.mesh.geometry.attributes.position
        positions.setXYZ(0, a.x, a.y, a.z)
        positions.setXYZ(1, b.x, b.y, b.z)
        positions.needsUpdate = true
        edge.mesh.geometry.computeBoundingSphere()
        edge.mesh.material.opacity = THREE.MathUtils.lerp(edge.mesh.material.opacity, targetOpacity, 0.12)

        // VIEW-LAYER DE-EMPHASIS ONLY (same guarantee as node de-emphasis above)
        if (deemphasizeGroupsRef.current.size > 0 && !edge.diffState) {
          const isDeemphasizedEdge =
            (deemphasizeGroupsRef.current.has('BCAST') && (isBcastIp(edge.dst) || isBcastIp(edge.src))) ||
            (deemphasizeGroupsRef.current.has('MCAST') && (isMcastIp(edge.dst) || isMcastIp(edge.src)))
          if (isDeemphasizedEdge) {
            edge.mesh.material.opacity = THREE.MathUtils.lerp(edge.mesh.material.opacity, 0.015, 0.1)
          }
        }

        // Diff state for edges
        if (edge.diffState === 'added') {
          if (edge.mesh.material.color.getHex() !== 0x34d399) edge.mesh.material.color.setHex(0x34d399)
          edge.mesh.material.opacity = Math.sin(performance.now() / 1000 * 3.0) * 0.3 + 0.6
        } else {
          if (edge.mesh.material.color.getHex() !== 0xf2f2f5) edge.mesh.material.color.setHex(0xf2f2f5)
          if (diffModeRef.current && !edge.diffState) {
            edge.mesh.material.opacity = THREE.MathUtils.lerp(edge.mesh.material.opacity, 0.02, 0.1)
          }
        }

        // Path trace — cyan for path edges, near-invisible for everything else
        if (pathActive) {
          if (pathEdgeKeys.has(edge.key)) {
            edge.mesh.material.color.setHex(0x22d3ee)
            edge.mesh.material.opacity = THREE.MathUtils.lerp(edge.mesh.material.opacity, 0.92, 0.12)
          } else {
            edge.mesh.material.opacity = THREE.MathUtils.lerp(edge.mesh.material.opacity, 0.03, 0.1)
          }
        }

        edge.recentBytes *= 0.88
        edge.recentPackets *= 0.86
      })
    }

    function updatePackets() {
      const remove = []
      const pointTarget = pointTargetRef.current
      const depths = pointTarget.active && pointTarget.ip ? focusDepths(pointTarget.ip) : null

      packetStore.forEach((packet, index) => {
        const src = nodeStore.get(packet.src)
        const dst = nodeStore.get(packet.dst)
        if (!src || !dst || !src.group.visible || !dst.group.visible) {
          scene.remove(packet.mesh)
          remove.push(index)
          return
        }

        packet.progress += packet.speed
        if (packet.progress >= 1) {
          scene.remove(packet.mesh)
          packet.mesh.geometry.dispose()
          packet.mesh.material.dispose()
          remove.push(index)
          return
        }

        packet.mesh.position.set(
          src.x + (dst.x - src.x) * packet.progress,
          src.y + (dst.y - src.y) * packet.progress,
          src.z + (dst.z - src.z) * packet.progress,
        )
        if (depths) {
          const inFocus = depths.has(packet.src) && depths.has(packet.dst)
          packet.mesh.material.opacity = THREE.MathUtils.lerp(packet.mesh.material.opacity, inFocus ? 0.96 : 0.08, 0.18)
        } else {
          packet.mesh.material.opacity = THREE.MathUtils.lerp(packet.mesh.material.opacity, 0.96, 0.18)
        }
      })

      remove.reverse().forEach((index) => packetStore.splice(index, 1))
    }

    ingestPacketRef.current = ingestPacket
    resetGraphRef.current = clearGraph
    // Expose plain-data copies of nodeStore/edgeStore for checkpoint serialization
    snapshotGraphRef.current = function captureGraphData() {
      const nodeMap = new Map()
      nodeStore.forEach((n, ip) => nodeMap.set(ip, { ip, bytes: n.bytes, packets: n.packets, mac: n.mac }))
      const edgeMap = new Map()
      edgeStore.forEach((e, key) => edgeMap.set(key, { src: e.src, dst: e.dst, bytes: e.bytes, packets: e.packets }))
      return { nodeStore: nodeMap, edgeStore: edgeMap }
    }
    rebuildGraphRef.current = rebuildGraph

    // Apply diff visual states to nodeStore and edgeStore entries
    applyDiffStateRef.current = function(diffResult) {
      const addedSet = new Set(diffResult.addedNodes.map(n => n.ip))
      const changedMap = new Map(diffResult.changedNodes.map(n => [n.ip, n]))
      nodeStore.forEach((node, ip) => {
        if (addedSet.has(ip)) node.diffState = 'added'
        else if (changedMap.has(ip)) {
          node.diffState = changedMap.get(ip).bytesDelta > 0 ? 'increased' : 'decreased'
        } else {
          node.diffState = 'unchanged'
        }
      })

      // Edges — mark added edges (both key orderings)
      const addedEdgeKeys = new Set(
        diffResult.addedEdges.flatMap(e => [`${e.src}<->${e.dst}`, `${e.dst}<->${e.src}`])
      )
      edgeStore.forEach((edge, key) => {
        edge.diffState = addedEdgeKeys.has(key) ? 'added' : null
      })
    }
    clearDiffStateRef.current = function() {
      nodeStore.forEach(node => { delete node.diffState })
      edgeStore.forEach(edge => { delete edge.diffState })
    }

    // queueAutoCheckpointRef.current is set in the component body to point at queueAutoCheckpoint()
    // so it can be called from inside this closure without a circular dependency.

    function updateLayoutSpread() {
      const spread = layoutSpreadRef.current
      spread.target = THREE.MathUtils.clamp(spread.target, MIN_LAYOUT_SPREAD, MAX_LAYOUT_SPREAD)
      spread.value = THREE.MathUtils.lerp(spread.value, spread.target, 0.075)
    }

    function animate() {
      frameRef.current = requestAnimationFrame(animate)
      updateLayoutSpread()
      updateGraphVisuals()
      updatePackets()
      if (!orbitActive && !userHasPanned) updateOrbitTarget()
      if (screensaverActiveRef.current) {
        if (!screensaverRef.current.initialized) {
          screensaverRef.current.initialized = true
          const offset = camera.position.clone().sub(controls.target)
          screensaverRef.current.radius = Math.sqrt(offset.x * offset.x + offset.z * offset.z)
          screensaverRef.current.y = camera.position.y
          screensaverRef.current.spinAngle = Math.atan2(offset.x, offset.z)
        }
        screensaverRef.current.spinAngle += 0.002
        const r = screensaverRef.current.radius
        const angle = screensaverRef.current.spinAngle
        camera.position.set(
          controls.target.x + r * Math.sin(angle),
          screensaverRef.current.y,
          controls.target.z + r * Math.cos(angle),
        )
        camera.lookAt(controls.target)
      }
      controls.update()

      // cull labels by distance — only show closest 8 nodes within camera frame
      const MAX_VISIBLE_LABELS = 8
      const cameraPos = camera.position
      const selected = selectedIpRef.current

      // build frustum from current camera matrices so only in-frame nodes compete for label slots
      camera.updateWorldMatrix(true, false)
      const _frustum = new THREE.Frustum()
      _frustum.setFromProjectionMatrix(
        new THREE.Matrix4().multiplyMatrices(camera.projectionMatrix, camera.matrixWorldInverse)
      )
      const inFrustum = (n) => _frustum.containsPoint(new THREE.Vector3(n.x, n.y, n.z))

      if (selected && nodeStore.has(selected)) {
        // subcluster mode — cull within neighborhood only
        const adjacency = new Map()
        edgeStore.forEach((edge) => {
          if (!adjacency.has(edge.src)) adjacency.set(edge.src, new Set())
          if (!adjacency.has(edge.dst)) adjacency.set(edge.dst, new Set())
          adjacency.get(edge.src).add(edge.dst)
          adjacency.get(edge.dst).add(edge.src)
        })
        const neighbors = new Set([selected, ...(adjacency.get(selected) || [])])

        const subclusterByDistance = [...nodeStore.values()]
          .filter(n => n.group.visible && neighbors.has(n.ip) && inFrustum(n))
          .map(n => ({
            node: n,
            dist: cameraPos.distanceTo(new THREE.Vector3(n.x, n.y, n.z))
          }))
          .sort((a, b) => a.dist - b.dist)

        const outsideByDistance = [...nodeStore.values()]
          .filter(n => n.group.visible && !neighbors.has(n.ip))
          .map(n => ({
            node: n,
            dist: cameraPos.distanceTo(new THREE.Vector3(n.x, n.y, n.z))
          }))
          .sort((a, b) => a.dist - b.dist)

        subclusterByDistance.forEach(({ node }, index) => {
          node.label.visible = showLabelsRef.current && index < MAX_VISIBLE_LABELS
        })

        // hide all labels outside subcluster
        outsideByDistance.forEach(({ node }) => {
          node.label.visible = false
        })

      } else {
        // global mode — cull across all visible in-frame nodes
        const nodesByDistance = [...nodeStore.values()]
          .filter(n => n.group.visible && inFrustum(n))
          .map(n => ({
            node: n,
            dist: cameraPos.distanceTo(new THREE.Vector3(n.x, n.y, n.z))
          }))
          .sort((a, b) => a.dist - b.dist)

        nodesByDistance.forEach(({ node }, index) => {
          node.label.visible = showLabelsRef.current && index < MAX_VISIBLE_LABELS
        })
      }

      // Feature 8 — always show hovered and pinned labels
      if (hoveredIpRef.current && nodeStore.has(hoveredIpRef.current)) {
        nodeStore.get(hoveredIpRef.current).label.visible = showLabelsRef.current
      }
      pinnedIpsRef.current.forEach(ip => {
        if (nodeStore.has(ip)) nodeStore.get(ip).label.visible = showLabelsRef.current
      })

      nodeStore.forEach((node) => {
        node.label.quaternion.copy(camera.quaternion)
        node.ring.quaternion.copy(camera.quaternion)
          .multiply(_spinQ.setFromAxisAngle(_zAxis, node.ringSpinAngle))
      })

      renderer.render(scene, camera)
    }

    let pointerDownPos = null

    function handlePointerDown(event) {
      pointerDownPos = { x: event.clientX, y: event.clientY }
      if (event.shiftKey) return
      const bounds = renderer.domElement.getBoundingClientRect()
      pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1
      pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1
      raycaster.setFromCamera(pointer, camera)
      const meshes = [...nodeStore.values()].filter(n => n.group.visible).map(n => n.mesh)
      const hit = raycaster.intersectObjects(meshes, false)[0]
      if (hit?.object?.userData?.ip) {
        pointerLockedIpRef.current = hit.object.userData.ip
        pointTargetRef.current = { active: true, ip: hit.object.userData.ip, x: 0, y: 0 }
        setSelectedIp(hit.object.userData.ip)
        if (event.button === 0) controls.enabled = false
      } else {
        controls.enabled = true
      }
    }

    function handlePointerMove(event) {
      const bounds = renderer.domElement.getBoundingClientRect()
      pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1
      pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1
      raycaster.setFromCamera(pointer, camera)
      const meshes = [...nodeStore.values()].filter(n => n.group.visible).map(n => n.mesh)
      const hit = raycaster.intersectObjects(meshes, false)[0]
      const ip = hit?.object?.userData?.ip || null
      hoveredIpRef.current = ip

      // Diff tooltip
      const diff = activeDiffRef.current
      if (ip && diff) {
        const node = nodeStore.get(ip)
        const ds = node?.diffState
        if (ds && ds !== 'unchanged') {
          let text
          if (ds === 'added') {
            text = 'Added in compare state'
          } else {
            const changed = diff.result.changedNodes.find(n => n.ip === ip)
            text = changed ? changed.reason : ds === 'increased' ? '↑ traffic' : '↓ traffic'
          }
          setDiffReasonTooltipRef.current({ ip, x: event.clientX, y: event.clientY, text })
          return
        }
      }
      setDiffReasonTooltipRef.current(null)
    }

    function handlePointerLeave() {
      hoveredIpRef.current = null
      setDiffReasonTooltipRef.current(null)
    }

    function handlePointerUp(event) {
      controls.enabled = true
      const moved = pointerDownPos
        ? Math.hypot(event.clientX - pointerDownPos.x, event.clientY - pointerDownPos.y)
        : 0
      pointerDownPos = null
      if (moved > 5) return
      if (selectedIpRef.current) {
        const bounds = renderer.domElement.getBoundingClientRect()
        pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1
        pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1
        raycaster.setFromCamera(pointer, camera)
        const meshes = [...nodeStore.values()].filter(n => n.group.visible).map(n => n.mesh)
        const hit = raycaster.intersectObjects(meshes, false)[0]
        if (!hit) setSelectedIp(null)
      }
    }

    function handleResize() {
      camera.aspect = mount.clientWidth / mount.clientHeight
      camera.updateProjectionMatrix()
      renderer.setSize(mount.clientWidth, mount.clientHeight)
    }

    renderer.domElement.addEventListener('pointerdown', handlePointerDown)
    renderer.domElement.addEventListener('pointerup', handlePointerUp)
    renderer.domElement.addEventListener('pointermove', handlePointerMove)
    renderer.domElement.addEventListener('pointerleave', handlePointerLeave)
    window.addEventListener('resize', handleResize)
    animate()

    const ws = new WebSocket(WS_URL)
    websocketRef.current = ws
    ws.addEventListener('open', () => {
      setStatus('starting')
      ws.send(JSON.stringify({ type: 'start_capture' }))
    })

    ws.addEventListener('message', (event) => {
      let data
      try { data = JSON.parse(event.data) } catch { return }
      if (data.type === 'packet') {
        const packet = normalizePacket(data, 'live', Date.now())
        livePacketsRef.current.push(packet)
        if (livePacketsRef.current.length > LIVE_PACKET_HISTORY_LIMIT) {
          livePacketsRef.current.splice(0, livePacketsRef.current.length - LIVE_PACKET_HISTORY_LIMIT)
        }
        if (livePacketFlushRef.current === null) {
          livePacketFlushRef.current = window.setTimeout(() => {
            livePacketFlushRef.current = null
            setLivePackets([...livePacketsRef.current])
          }, LIVE_PACKET_UI_FLUSH_MS)
        }
        if (appModeRef.current === 'live' && activeSourceRef.current === 'live' && packetMatchesFilter(packet, activeFilterRef.current) && !timeRangeRef.current && !liveTimeRef.current) {
          ingestPacket(packet)
        }
      }
      if (data.type === 'nodes' && appModeRef.current === 'live') applyNodeSummary(data.nodes || [])
      if (data.type === 'capture_status') {
        if (data.iface && data.iface !== 'default interface') setCaptureInterface(data.iface)
        if (data.status === 'ready') setStatus('ready')
        if (data.status === 'running') setStatus('live')
        if (data.status === 'error') setStatus('capture_error')
      }
    })

    ws.addEventListener('error', () => {
      setStatus('offline')
    })
    ws.addEventListener('close', () => {
      setStatus('offline')
    })

    return () => {
      if (livePacketFlushRef.current !== null) window.clearTimeout(livePacketFlushRef.current)
      if (analysisSnapshotTimerRef.current !== null) window.clearTimeout(analysisSnapshotTimerRef.current)
      if (graphRebuildTimerRef.current !== null) window.clearTimeout(graphRebuildTimerRef.current)
      if (autoCheckpointTimerRef.current !== null) window.clearTimeout(autoCheckpointTimerRef.current)
      if (orbitActiveCooldown) clearTimeout(orbitActiveCooldown)
      ws.close()
      cancelAnimationFrame(frameRef.current)
      renderer.domElement.removeEventListener('pointermove', handlePointerMove)
      renderer.domElement.removeEventListener('pointerleave', handlePointerLeave)
      window.removeEventListener('resize', handleResize)
      controls.dispose()

      nodeStore.forEach((node) => {
        scene.remove(node.group)
        node.mesh.material.dispose()
        node.label.material.map.dispose()
        node.label.material.dispose()
        node.ring.geometry.dispose()
        node.ring.material.dispose()
      })
      edgeStore.forEach((edge) => {
        scene.remove(edge.mesh)
        edge.mesh.geometry.dispose()
        edge.mesh.material.dispose()
      })
      packetStore.forEach((packet) => {
        scene.remove(packet.mesh)
        packet.mesh.material.dispose()
      })
      nodeGeometry.dispose()
      packetGeometry.dispose()
      ingestPacketRef.current = null
      resetGraphRef.current = null
      snapshotGraphRef.current = null
      rebuildGraphRef.current = null
      applyDiffStateRef.current = null
      clearDiffStateRef.current = null
      cameraRef.current = null
      renderer.dispose()

      if (mount.contains(renderer.domElement)) {
        mount.removeChild(renderer.domElement)
      }
    }
  }, [])

  useEffect(() => {
    if (!gesturesEnabled) {
      gestureCleanupRef.current?.()
      gestureCleanupRef.current = null
      return
    }

    useEffect(() => {
      if (!mountRef.current) return
      const mount = mountRef.current
      const canvas = mount.querySelector('canvas')
      if (!canvas) return
      const observer = new ResizeObserver(() => {
        if (!cameraRef.current) return
        cameraRef.current.aspect = mount.clientWidth / mount.clientHeight
        cameraRef.current.updateProjectionMatrix()
      })
      observer.observe(mount)
      return () => observer.disconnect()
    }, [])

    const cam = cameraRef
    const nodes = nodesRef

    import('./useHandGestures.js').then((module) => {
      const init = module.useHandGestures({
        cameraRef: cam,
        layoutSpreadRef,
        onPointAt: ({
          active,
          mode = 'pointer',
          x,
          y,
          lockKind = null,
          lockProgress = 0,
          locked = false,
          selectionLockComplete = false,
          openHand = false,
        }) => {
          if (!active) {
            const lockedIp = pointerLockedIpRef.current
            pointTargetRef.current = { active: Boolean(lockedIp), ip: lockedIp, x: 0, y: 0 }
            setPointReticle((current) => ({
              ...current,
              active: false,
              locked: false,
              lockKind: null,
              lockProgress: 0,
            }))
            return
          }

          if (!cam.current) return

          const canvasBounds = mountRef.current?.getBoundingClientRect()
          const viewportBounds = mountRef.current?.parentElement?.getBoundingClientRect()
          if (!canvasBounds || !viewportBounds) return

          const pointerPx = {
            x: ((x + 1) / 2) * canvasBounds.width,
            y: ((1 - y) / 2) * canvasBounds.height,
          }
          const reticleX = canvasBounds.left - viewportBounds.left + pointerPx.x
          const reticleY = canvasBounds.top - viewportBounds.top + pointerPx.y

          if (openHand) {
            pointerLockedIpRef.current = null
            pointTargetRef.current = { active: false, ip: null, x, y }
            if (selectedIpRef.current) setSelectedIp(null)
            setPointReticle({
              active: true,
              locked: false,
              x: reticleX,
              y: reticleY,
              lockKind: null,
              lockProgress: 0,
              mode,
            })
            return
          }

          if (mode !== 'pointer') {
            const lockedIp = pointerLockedIpRef.current
            pointTargetRef.current = { active: Boolean(lockedIp), ip: lockedIp, x, y }
            setPointReticle({
              active: true,
              locked: Boolean(lockedIp) || locked,
              x: reticleX,
              y: reticleY,
              lockKind,
              lockProgress,
              mode,
            })
            return
          }

          let hitIp = null
          let bestDistance = TARGET_PIXEL_TOLERANCE * 1.45

          nodes.current.forEach((node) => {
            if (!node.group.visible) return
            const projected = new THREE.Vector3(node.x, node.y, node.z).project(cam.current)
            if (projected.z < -1 || projected.z > 1) return
            const nodePx = {
              x: ((projected.x + 1) / 2) * canvasBounds.width,
              y: ((1 - projected.y) / 2) * canvasBounds.height,
            }
            const distance = Math.hypot(nodePx.x - pointerPx.x, nodePx.y - pointerPx.y)
            if (distance > bestDistance) return
            bestDistance = distance
            hitIp = node.ip
          })

          if (selectionLockComplete && hitIp && !pointerLockedIpRef.current) {
            pointerLockedIpRef.current = hitIp
            if (selectedIpRef.current !== hitIp) setSelectedIp(hitIp)
          }

          const lockedIp = pointerLockedIpRef.current
          const focusIp = lockedIp || hitIp
          pointTargetRef.current = { active: Boolean(focusIp), ip: focusIp, x, y }

          if (hitIp) {
            setPointReticle({
              active: true,
              locked: Boolean(lockedIp) || selectionLockComplete,
              x: reticleX,
              y: reticleY,
              lockKind: lockedIp ? null : lockKind,
              lockProgress: lockedIp ? 0 : lockProgress,
              mode,
            })
          } else {
            setPointReticle({
              active: true,
              locked: Boolean(lockedIp),
              x: reticleX,
              y: reticleY,
              lockKind: null,
              lockProgress: 0,
              mode,
            })
          }
        },
      })
      init?.().then(cleanup => {
        gestureCleanupRef.current = cleanup
      }).catch(err => console.error('Gesture init failed:', err))
    })

    return () => {
      gestureCleanupRef.current?.()
      gestureCleanupRef.current = null
    }
  }, [gesturesEnabled])

  useEffect(() => {
    if (graphRebuildTimerRef.current !== null) {
      clearTimeout(graphRebuildTimerRef.current)
      graphRebuildTimerRef.current = null
    }
    if (!rebuildGraphRef.current) return
    if (activeSource === 'replay') {
      rebuildGraphRef.current(filteredPacketsRef.current)
      lastIngestedReplayIndexRef.current = replayIndexRef.current
      return
    }
    graphRebuildTimerRef.current = window.setTimeout(() => {
      graphRebuildTimerRef.current = null
      rebuildGraphRef.current?.(filteredPacketsRef.current)
    }, LIVE_GRAPH_REBUILD_MS)
    return () => {
      if (graphRebuildTimerRef.current !== null) {
        clearTimeout(graphRebuildTimerRef.current)
        graphRebuildTimerRef.current = null
      }
    }
  }, [activeFilter, activeSource])

  useEffect(() => {
    if (activeSource !== 'replay') return
    if (!ingestPacketRef.current || !rebuildGraphRef.current) return

    const from = lastIngestedReplayIndexRef.current
    const to = replayIndex

    const SEEK_THRESHOLD = 500
    if (to < from || to > from + SEEK_THRESHOLD) {
      rebuildGraphRef.current(filteredPacketsRef.current)
      lastIngestedReplayIndexRef.current = to
      return
    }

    const allPackets = replayPacketsRef.current
    for (let i = from; i < to && i < allPackets.length; i++) {
      const pkt = allPackets[i]
      if (packetMatchesFilter(pkt, activeFilterRef.current)) {
        ingestPacketRef.current(pkt)
      }
    }
    lastIngestedReplayIndexRef.current = to
  }, [replayIndex, activeSource])

  useEffect(() => {
    if (selectedPacketId && !filteredPackets.some((packet) => packet.id === selectedPacketId)) {
      setSelectedPacketId(null)
    }
  }, [filteredPackets, selectedPacketId])

  function requestCapture() {
    setActiveTab('live')
    setAppMode('live')
    setActiveSource('live')
    setReplayState('idle')
    resetGraphRef.current?.()

    if (websocketRef.current?.readyState !== WebSocket.OPEN) {
      setStatus('offline')
      return
    }

    setStatus('starting')
    websocketRef.current.send(JSON.stringify({ type: 'start_capture' }))
  }

  function handleFilterInput(e) {
    const val = e.target.value
    setFilterInput(val)
    const activeToken = val.includes('&&') ? val.split('&&').pop().trim().toLowerCase() : val.trim().toLowerCase()
    setFilterSuggestions(activeToken ? FILTER_SUGGESTIONS.filter(s => s.startsWith(activeToken)) : FILTER_SUGGESTIONS)
    setSuggestionIndex(-1)
  }

  function handleFilterFocus() {
    const val = filterInput
    const activeToken = val.includes('&&') ? val.split('&&').pop().trim().toLowerCase() : val.trim().toLowerCase()
    setFilterSuggestions(activeToken ? FILTER_SUGGESTIONS.filter(s => s.startsWith(activeToken)) : FILTER_SUGGESTIONS)
  }

  function handleFilterBlur() {
    setTimeout(() => setFilterSuggestions([]), 150)
  }

  function handleFilterKeyDown(e) {
    if (!filterSuggestions.length) return
    if (e.key === 'ArrowDown') { e.preventDefault(); setSuggestionIndex(i => Math.min(i + 1, filterSuggestions.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSuggestionIndex(i => Math.max(i - 1, 0)) }
    if (e.key === 'Enter' && suggestionIndex >= 0) { e.preventDefault(); pickSuggestion(filterSuggestions[suggestionIndex]) }
    if (e.key === 'Escape') setFilterSuggestions([])
  }

  function pickSuggestion(s) {
    if (filterInput.includes('&&')) {
      const parts = filterInput.split('&&')
      parts[parts.length - 1] = ' ' + s
      setFilterInput(parts.join('&&'))
    } else {
      setFilterInput(s)
    }
    setFilterSuggestions([])
    setSuggestionIndex(-1)
  }

  function applyDisplayFilter(event) {
    event.preventDefault()
    try {
      const nextFilter = parseDisplayFilter(filterInput)
      setActiveFilter(nextFilter)
      setFilterError('')
    } catch (error) {
      setFilterError(error instanceof Error ? error.message : 'Unsupported display filter.')
    }
  }

  function clearDisplayFilter() {
    setFilterInput('')
    setActiveFilter({ raw: '', type: 'all' })
    setFilterError('')
  }

  async function handleReplayFile(event) {
    const file = event.target.files?.[0]
    if (!file) return

    setActiveTab('live')
    setAppMode('replay')
    setActiveSource('replay')
    setReplayError('')
    setReplayState('idle')
    setReplayIndex(0)
    setReplayTime(0)
    resetGraphRef.current?.()

    try {
      const parsed = parseCaptureBuffer(await file.arrayBuffer())
      const normalizedReplayPackets = parsed.packets.map((packet, index) => normalizePacket(packet, 'replay', index))
      setReplayPackets(normalizedReplayPackets)
      setAnalysisSnapshot(buildTrafficAnalysis(normalizedReplayPackets.slice(0, ANALYSIS_PACKET_WINDOW), {
        duration: parsed.duration,
      }, conversationSort))
      setReplayMeta({
        name: file.name,
        format: parsed.format,
        parsed: parsed.packets.length,
        skipped: parsed.skipped,
        duration: parsed.duration,
        linkTypes: parsed.linkTypes || [],
      })
      setReplayState(parsed.packets.length ? 'playing' : 'idle')
      if (parsed.packets.length) {
        setTimeRange({ start: 0, end: parsed.duration })
      }
      if (!parsed.packets.length) {
        const linkTypes = parsed.linkTypes?.length
          ? parsed.linkTypes.map(linkTypeLabel).join(', ')
          : 'unknown link type'
        setReplayError(
          `No supported IP packets were found. Format: ${parsed.format}; detected: ${linkTypes}; skipped: ${parsed.skipped.toLocaleString()}.`,
        )
      }
    } catch (error) {
      setReplayPackets([])
      setReplayMeta(null)
      setReplayIndex(0)
      setReplayTime(0)
      setTimeRange(null)
      setReplayError(error instanceof Error ? error.message : 'Could not parse that capture file.')
    } finally {
      event.target.value = ''
    }
  }

  function restartReplay(nextState = 'playing') {
    resetGraphRef.current?.()
    setReplayIndex(0)
    setReplayTime(0)
    setReplayState(replayPackets.length ? nextState : 'idle')
  }

  function handleTimelinePointerDown(e) {
    if (!timelineBounds || !trackRef.current) return
    e.currentTarget.setPointerCapture(e.pointerId)
    const rect = trackRef.current.getBoundingClientRect()
    const span = timelineBounds.max - timelineBounds.min
    const x = e.clientX - rect.left
    const W = rect.width
    const tAtX = timelineBounds.min + Math.max(0, Math.min(1, x / W)) * span
    const ds = dragStateRef.current
    ds.startTime = tAtX
    ds.movedEnough = false

    if (timeRange) {
      const leftPx  = ((timeRange.start - timelineBounds.min) / span) * W
      const rightPx = ((timeRange.end   - timelineBounds.min) / span) * W
      {
        const scrubT0 = activeSource === 'replay' ? replayTime : (liveTime ?? timelineBounds.max)
        const playPx = ((scrubT0 - timelineBounds.min) / span) * W
        if (Math.abs(x - playPx) <= 7) { ds.mode = 'playhead'; return }
      }
      if (Math.abs(x - leftPx)  <= 9) { ds.mode = 'windowLeft';  return }
      if (Math.abs(x - rightPx) <= 9) { ds.mode = 'windowRight'; return }
      if (x > leftPx + 9 && x < rightPx - 9) {
        ds.mode = 'windowBody'
        ds.startWindowStart = timeRange.start
        ds.startWindowEnd   = timeRange.end
        return
      }
    }
    ds.mode = 'playheadOrDraw'
    ds.startWindowStart = tAtX
  }

  function handleTimelinePointerMove(e) {
    const ds = dragStateRef.current
    if (!ds.mode || !timelineBounds || !trackRef.current) return
    const rect = trackRef.current.getBoundingClientRect()
    const span = timelineBounds.max - timelineBounds.min
    const t = timelineBounds.min + Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width)) * span
    const threshold = span * 0.008

    if (ds.mode === 'playheadOrDraw' && Math.abs(t - ds.startTime) > threshold) {
      ds.mode = 'drawing'
      ds.movedEnough = true
    }

    switch (ds.mode) {
      case 'playhead': {
        const t2 = timeRange
          ? Math.max(timeRange.start, Math.min(timeRange.end, t))
          : t
        if (activeSource === 'replay') scrubReplay(t2)
        else if (activeSource === 'live') setLiveTime(t2)
        break
      }
      case 'windowLeft':
        setTimeRange(r => r ? { ...r, start: Math.max(timelineBounds.min, Math.min(t, r.end - threshold)) } : r)
        break
      case 'windowRight':
        setTimeRange(r => r ? { ...r, end: Math.min(timelineBounds.max, Math.max(t, r.start + threshold)) } : r)
        break
      case 'windowBody': {
        const dur = ds.startWindowEnd - ds.startWindowStart
        const delta = t - ds.startTime
        const ns = Math.max(timelineBounds.min, Math.min(timelineBounds.max - dur, ds.startWindowStart + delta))
        setTimeRange({ start: ns, end: ns + dur })
        break
      }
      case 'drawing': {
        const s   = Math.min(ds.startWindowStart, t)
        const end = Math.max(ds.startWindowStart, t)
        setTimeRange({ start: Math.max(timelineBounds.min, s), end: Math.min(timelineBounds.max, end) })
        break
      }
    }
  }

  function handleTimelinePointerUp(e) {
    const ds = dragStateRef.current
    if (!ds.mode) return
    try { e.currentTarget.releasePointerCapture(e.pointerId) } catch {}

    if (ds.mode === 'playheadOrDraw') {
      if (activeSource === 'replay' && replayMeta) scrubReplay(ds.startTime)
      else if (activeSource === 'live') setLiveTime(ds.startTime)
      ds.mode = null
      return
    }
    if (ds.mode === 'drawing' && timelineBounds) {
      const span = timelineBounds.max - timelineBounds.min
      if (!timeRange || (timeRange.end - timeRange.start) < span * 0.008) {
        setTimeRange(null)
        if (activeSource === 'replay' && replayMeta) scrubReplay(ds.startTime)
        else if (activeSource === 'live') setLiveTime(ds.startTime)
      }
    }
    ds.mode = null
    ds.movedEnough = false
  }

  function scrubReplay(value) {
    const nextTime = Number(value)
    if (!Number.isFinite(nextTime)) return

    resetGraphRef.current?.()
    let nextIndex = 0
    while (nextIndex < replayPackets.length && replayPackets[nextIndex].replayTime <= nextTime) {
      nextIndex += 1
    }
    setReplayIndex(nextIndex)
    setReplayTime(nextTime)
    setReplayState('paused')
  }

  useEffect(() => {
    if (replayState !== 'playing' || appMode !== 'replay' || !replayPackets.length) return undefined

    let lastTick = performance.now()
    const timer = window.setInterval(() => {
      const now = performance.now()
      const elapsed = ((now - lastTick) / 1000) * replaySpeed
      lastTick = now

      setReplayTime((currentTime) => {
        const duration = replayMeta?.duration || 0
        const nextTime = Math.min(currentTime + elapsed, duration)

        setReplayIndex((currentIndex) => {
          let nextIndex = currentIndex
          while (nextIndex < replayPackets.length && replayPackets[nextIndex].replayTime <= nextTime) {
            nextIndex += 1
          }
          if (nextIndex >= replayPackets.length && nextTime >= duration) {
            setReplayState('ended')
          }
          return nextIndex
        })

        return nextTime
      })
    }, REPLAY_TICK_MS)

    return () => window.clearInterval(timer)
  }, [appMode, replayMeta, replayPackets, replaySpeed, replayState])

  const currentThroughput = trafficAnalysis.throughput
  const protocolTotalBytes = Math.max(
    trafficAnalysis.protocols.reduce((total, protocol) => total + protocol.bytes, 0),
    1,
  )

  const packetDetails = selectedPacket
    ? [
      ['Frame', `${selectedPacket.id} · ${byteLabel(selectedPacket.size)}`],
      ['Ethernet', `${selectedPacket.srcMac || 'unknown'} -> ${selectedPacket.dstMac || 'unknown'}`],
      ['Network', `${selectedPacket.src || selectedPacket.srcIp} -> ${selectedPacket.dst || selectedPacket.dstIp}`],
      ['Transport', packetInfo(selectedPacket)],
    ]
    : []

  const packetBytesText = selectedPacket
    ? [
      `0000  ${String(selectedPacket.srcMac || 'unknown').padEnd(17)}  ${String(selectedPacket.dstMac || 'unknown').padEnd(17)}`,
      `0010  ${String(selectedPacket.src || selectedPacket.srcIp).padEnd(20)} -> ${String(selectedPacket.dst || selectedPacket.dstIp)}`,
      `0020  proto=${selectedPacket.proto || 'OTHER'} len=${selectedPacket.size || 0} sport=${selectedPacket.srcPort || '-'} dport=${selectedPacket.dstPort || '-'}`,
    ].join('\n')
    : 'Select a packet to inspect bytes.'

  const reticleScale = THREE.MathUtils.clamp(1 / cameraZoom, 0.72, 1.35)

  // ── Checkpoint handlers ──────────────────────────────────

  function takeCheckpoint(opts = {}) {
    const graphData = snapshotGraphRef.current?.()
    if (!graphData) return null
    const serialized = serializeCheckpoint(graphData.nodeStore, graphData.edgeStore, trafficAnalysis)
    const cp = {
      id: crypto.randomUUID(),
      label: opts.label || `Checkpoint ${new Date().toLocaleTimeString()}`,
      createdAt: Date.now(),
      source: activeSourceRef.current,
      type: opts.type || 'manual',
      reason: opts.reason || null,
      eventSummary: opts.eventSummary || [],
      ...serialized,
    }
    setCheckpoints(prev => {
      const next = [...prev, cp]
      return next.length > 50 ? next.slice(next.length - 50) : next
    })
    return cp
  }

  function queueAutoCheckpoint(reason) {
    if (autoCheckpointMode === 'off') return
    autoCheckpointQueueRef.current.push(reason)
    if (autoCheckpointTimerRef.current) return
    autoCheckpointTimerRef.current = window.setTimeout(() => {
      autoCheckpointTimerRef.current = null
      const reasons = autoCheckpointQueueRef.current.splice(0)
      const unique = [...new Set(reasons)]
      const label = unique.length === 1 ? `Auto: ${unique[0]}` : `Auto: ${unique.length} Network Changes`
      takeCheckpoint({ type: 'auto', reason: unique[0], eventSummary: unique, label })
    }, 4000)
  }

  function buildCurrentState() {
    const graphData = snapshotGraphRef.current?.()
    if (!graphData) return null
    const serialized = serializeCheckpoint(graphData.nodeStore, graphData.edgeStore, trafficAnalysis)
    const protocolSummary = {}
    trafficAnalysis.protocols.forEach(p => { protocolSummary[p.proto] = { bytes: p.bytes, packets: p.packets } })
    return { ...serialized, protocolSummary }
  }

  function computeDiff(baseId, compareId = 'current') {
    const getState = (id) => {
      if (id === 'current') return buildCurrentState()
      return checkpoints.find(c => c.id === id) || null
    }
    const base = getState(baseId)
    const compare = getState(compareId)
    if (!base || !compare) return
    const result = computeCheckpointDiff(base, compare)
    setActiveDiff({ baseId, compareId, result })
    applyDiffStateRef.current?.(result)
  }

  function clearDiff() {
    setActiveDiff(null)
    setDiffMode(false)
    clearDiffStateRef.current?.()
  }

  function updateCheckpointLabel(id, label) {
    setCheckpoints(prev => prev.map(c => c.id === id ? { ...c, label: label.trim() || c.label } : c))
  }
  function startRename(cp) {
    setEditingCpId(cp.id)
    setEditingCpLabel(cp.label)
  }
  function commitRename() {
    if (editingCpId && editingCpLabel.trim()) updateCheckpointLabel(editingCpId, editingCpLabel)
    setEditingCpId(null)
    setEditingCpLabel('')
  }
  function fmtTs(ts) {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }
  function submitCheckpointLabel() {
    const label = pendingLabel.trim() || `Checkpoint ${new Date().toLocaleTimeString()}`
    takeCheckpoint({ label })
    setPendingLabel('')
    setLabelingOpen(false)
  }

  // Feature 1 — summary chip data
  const topTalker = trafficAnalysis.endpoints[0] || null
  const mostPeers = (() => {
    const peerCount = new Map()
    trafficAnalysis.conversations.forEach(c => {
      peerCount.set(c.src, (peerCount.get(c.src) || 0) + 1)
      peerCount.set(c.dst, (peerCount.get(c.dst) || 0) + 1)
    })
    let best = null, bestCount = 0
    peerCount.forEach((count, ip) => {
      if (count > bestCount) { best = ip; bestCount = count }
    })
    return best ? { ip: best, count: bestCount } : null
  })()
  const recentAlerts = alertsRef.current.slice(-5).reverse()
  const alertCount = alertsRef.current.length
  const filteredCheckpoints = checkpoints.filter(c => !c.source || c.source === activeSource)

  const nodeInspectionData = useMemo(() => {
    if (!selectedIp) return null
    const ipPkts = allAvailablePackets.filter(p => {
      const s = p.src || p.srcIp
      const d = p.dst || p.dstIp
      return s === selectedIp || d === selectedIp
    })
    if (!ipPkts.length) return null

    let bytes = 0
    const protos = new Set()
    const peerBytes = new Map()
    let mac = null

    for (const p of ipPkts) {
      bytes += p.size || 0
      if (p.proto) protos.add(p.proto)
      const s = p.src || p.srcIp
      const d = p.dst || p.dstIp
      const peer = s === selectedIp ? d : s
      if (peer) peerBytes.set(peer, (peerBytes.get(peer) || 0) + (p.size || 0))
      if (!mac && p.srcMac && s === selectedIp) mac = p.srcMac
      if (!mac && p.dstMac && d === selectedIp) mac = p.dstMac
    }

    const filteredIpPkts = ipPkts.filter(p =>
      activeProtocols.has(packetProtocolGroup(p)) &&
      packetMatchesFilter(p, activeFilter)
    )

    return {
      bytes,
      packets: ipPkts.length,
      protocols: [...protos].sort(),
      mac: mac || null,
      peers: [...peerBytes.entries()]
        .map(([ip, b]) => ({ ip, bytes: b }))
        .sort((a, b) => b.bytes - a.bytes),
      recentPackets: filteredIpPkts.slice(-60).reverse(),
    }
  }, [selectedIp, allAvailablePackets, activeProtocols, activeFilter])

  const ALL_PROTOCOLS = ['TCP','UDP','DNS','ARP','BCAST','MCAST','OTHER']
  const analysisContent = {
    live: () => (
      <section className={`controlDock${liveAnalysisCollapsed ? ' dockCollapsed' : ''}`} aria-label="Capture controls">
        {liveAnalysisCollapsed ? (
          /* ── Collapsed tab ── */
          <button className="dockTab" type="button" onClick={() => setLiveAnalysisCollapsed(false)} aria-label="Expand controls">
            <span className={`dockTabIcon dockTabIcon--${activeSource}`}>
              {activeSource === 'live' ? (
                <svg viewBox="0 0 10 10" fill="currentColor"><circle cx="5" cy="5" r="4.5" /></svg>
              ) : (
                <svg viewBox="0 0 10 10" fill="currentColor"><polygon points="1.5,1 9.5,5 1.5,9" /></svg>
              )}
            </span>
            {activeProtocols.size < ALL_PROTOCOLS.length && (
              <span className="dockFilterDot" title={`${ALL_PROTOCOLS.length - activeProtocols.size} protocol(s) filtered`} />
            )}
            <span className="dockTabChevron">›</span>
          </button>
        ) : (
          /* ── Expanded dock ── */
          <div className="dockInner">
            <div className="dockHeader">
              <span className="dockLabel">Capture</span>
              <button type="button" className="dockCollapseBtn" onClick={() => setLiveAnalysisCollapsed(true)} aria-label="Collapse">‹</button>
            </div>

            {/* Mode switcher */}
            <div className="dockModeSwitch">
              <button
                type="button"
                className={`dockModeBtn dockModeBtn--live${activeSource === 'live' ? ' active' : ''}`}
                onClick={() => { setActiveSource('live'); setAppMode('live'); setReplayState('idle') }}
              >
                <svg className="dockModeIcon" viewBox="0 0 10 10" fill="currentColor">
                  <circle cx="5" cy="5" r="4.5" />
                </svg>
                Live
              </button>
              <button
                type="button"
                className={`dockModeBtn dockModeBtn--pcap${activeSource === 'replay' ? ' active' : ''}`}
                onClick={() => { setActiveSource('replay'); setAppMode('replay') }}
              >
                <svg className="dockModeIcon" viewBox="0 0 10 10" fill="currentColor">
                  <polygon points="1.5,1 9.5,5 1.5,9" />
                </svg>
                PCAP
              </button>
            </div>

            {/* Protocol filter tray */}
            <div className="dockDivider" />
            <div className="dockFilterSection">
              <div className="dockSectionHeader">
                <span className="dockSectionLabel">Protocols</span>
                <button
                  type="button"
                  className="dockAllToggle"
                  onClick={() => setActiveProtocols(
                    activeProtocols.size === ALL_PROTOCOLS.length
                      ? new Set()
                      : new Set(ALL_PROTOCOLS)
                  )}
                >{activeProtocols.size === ALL_PROTOCOLS.length ? 'none' : 'all'}</button>
              </div>
              <div className="dockProtos">
                {ALL_PROTOCOLS.map(proto => (
                  <button
                    key={proto}
                    type="button"
                    className={`dockProtoChip${activeProtocols.has(proto) ? ' active' : ''}`}
                    onClick={() => setActiveProtocols(prev => {
                      const next = new Set(prev)
                      next.has(proto) ? next.delete(proto) : next.add(proto)
                      return next
                    })}
                  >{proto}</button>
                ))}
              </div>
            </div>

            {/* Replay controls */}
            {activeSource === 'replay' && (
              <>
                <div className="dockDivider" />
                <div className="sourcePanel">
                  <label className="uploadZone">
                    <input type="file" accept=".pcap,.pcapng" onChange={handleReplayFile} />
                    <strong>Upload .pcap or .pcapng</strong>
                  </label>
                  {replayError && <p className="permissionError">{replayError}</p>}
                  {replayMeta && (
                    <>
                      <dl className="replayStats">
                        <div><dt>File</dt><dd>{replayMeta.name}</dd></div>
                        <div><dt>Parsed</dt><dd>{replayMeta.parsed.toLocaleString()}</dd></div>
                        <div><dt>Skipped</dt><dd>{replayMeta.skipped.toLocaleString()}</dd></div>
                        <div><dt>Time</dt><dd>{replayTime.toFixed(1)}s</dd></div>
                      </dl>
                      <div className="playbackControls">
                        <button type="button" disabled={!replayPackets.length} onClick={() => setReplayState(replayState === 'playing' ? 'paused' : 'playing')}>{replayState === 'playing' ? 'Pause' : 'Play'}</button>
                        <button type="button" disabled={!replayPackets.length} onClick={() => restartReplay('paused')}>Restart</button>
                        <select value={replaySpeed} onChange={(event) => setReplaySpeed(Number(event.target.value))}>
                          {[0.25, 0.5, 1, 2, 4].map((speed) => <option key={speed} value={speed}>{speed}x</option>)}
                        </select>
                      </div>
                      <p className="noteText">{replayIndex.toLocaleString()} of {replayPackets.length.toLocaleString()} packets replayed.</p>
                    </>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* Path trace panel — anchored below the dock */}
        {!screensaverActive && pathTrace && (
          <div className="pathPanel">
            <div className="pathPanelHeader">
              <span className="pathPanelTitle">Observed Conversation Path</span>
              <span className="pathPanelEndpoints">{pathTrace.src} → {pathTrace.dst}</span>
            </div>
            {pathTrace.found ? (
              <>
                <div className="pathHops">
                  {pathTrace.hops.map((hop, i) => (
                    <div key={i} className="pathHop">
                      <span className="pathHopIps">{hop.src} → {hop.dst}</span>
                      <span className="pathHopStats">{hop.packets}p · {formatBytes(hop.bytes)}</span>
                    </div>
                  ))}
                </div>
                <div className="pathHopCount">{pathTrace.hops.length} hop{pathTrace.hops.length !== 1 ? 's' : ''}</div>
              </>
            ) : (
              <div className="pathNoPath">No path found in captured traffic</div>
            )}
          </div>
        )}
      </section>
    ),
  }

  return (
    <main className="appShell">
      <div className={[
          'appFrame',
          screensaverActive ? 'screensaverActive' : ''
        ].filter(Boolean).join(' ')}>
          <section
            className="viewport liveViewport"
            aria-label={`${TABS[activeTab]} packet map`}
          >
            {!screensaverActive && (
              <form className="trafficFilterBar" onSubmit={applyDisplayFilter}>
                <span>Display Filter</span>
                <div className="filterInputWrap">
                  <input
                    value={filterInput}
                    onChange={handleFilterInput}
                    onFocus={handleFilterFocus}
                    onBlur={handleFilterBlur}
                    onKeyDown={handleFilterKeyDown}
                    autoComplete="off"
                  />
                  {filterSuggestions.length > 0 && (
                    <ul className="filterSuggestions">
                      {filterSuggestions.map((s, i) => (
                        <li
                          key={s}
                          className={i === suggestionIndex ? 'active' : ''}
                          onMouseDown={() => pickSuggestion(s)}
                        >
                          {s}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="filterBarCheckpoints">
                  {labelingOpen
                    ? (
                      <div className="cpLabelForm">
                        <input
                          autoFocus
                          className="cpLabelInput"
                          placeholder={`Checkpoint ${new Date().toLocaleTimeString()}`}
                          value={pendingLabel}
                          onChange={e => setPendingLabel(e.target.value)}
                          onKeyDown={e => {
                            if (e.key === 'Enter') { e.preventDefault(); submitCheckpointLabel() }
                            if (e.key === 'Escape') { setLabelingOpen(false); setPendingLabel('') }
                          }}
                        />
                        <button type="button" className="cpSaveBtn" onClick={submitCheckpointLabel}>Save</button>
                        <button type="button" onClick={() => { setLabelingOpen(false); setPendingLabel('') }}>✕</button>
                      </div>
                    )
                    : <button type="button" className="cpSaveBtn" onClick={() => setLabelingOpen(true)}>Checkpoint</button>
                  }
                  <button
                    type="button"
                    className={['cpHistoryBtn', checkpointPanelOpen ? 'active' : ''].filter(Boolean).join(' ')}
                    onClick={() => setCheckpointPanelOpen(v => !v)}
                  >
                    History{filteredCheckpoints.length > 0 ? ` (${filteredCheckpoints.length})` : ''}
                  </button>
                </div>
                {filterError && <p className="filterError">{filterError}</p>}
              </form>
            )}

            {/* Feature 1 — Summary chips */}
            {!screensaverActive && (
              <div className="summaryChips">
                {topTalker && (
                  <button className="chip" type="button" onClick={() => setSelectedIp(topTalker.ip)}>
                    Top Talker: <strong>{topTalker.ip}</strong>
                  </button>
                )}
                {mostPeers && (
                  <button className="chip" type="button" onClick={() => setSelectedIp(mostPeers.ip)}>
                    Most Peers: <strong>{mostPeers.ip}</strong> ({mostPeers.count})
                  </button>
                )}
                {alertCount > 0 && (
                  <div className="chip chipAlert">
                    Alerts: <strong>{alertCount}</strong>
                    <div className="alertDropdown">
                      {recentAlerts.map((a, i) => (
                        <button key={i} type="button" onClick={() => setSelectedIp(a.ip)}>
                          {a.label} — {a.ip}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Checkpoint history panel */}
            {!screensaverActive && checkpointPanelOpen && (
              <div className="checkpointPanel">
                <div className="checkpointPanelHeader">
                  <span>Checkpoints</span>
                  <button type="button" onClick={() => setCheckpointPanelOpen(false)}>×</button>
                </div>
                <div className="cpModeSelector">
                  {['off', 'smart', 'aggressive'].map(m => (
                    <button
                      key={m}
                      type="button"
                      className={autoCheckpointMode === m ? 'active' : ''}
                      onClick={() => setAutoCheckpointMode(m)}
                    >{m}</button>
                  ))}
                </div>
                {referenceId && (() => {
                  const refCp = checkpoints.find(c => c.id === referenceId)
                  if (!refCp) return null
                  return (
                    <div className="cpReferenceBar">
                      <span className="cpRefLabel">Reference: <strong>{refCp.label}</strong></span>
                      <button type="button" onClick={() => computeDiff(referenceId, 'current')}>vs Current</button>
                      <button type="button" className="cpRefClear" onClick={() => setReferenceId(null)}>Clear</button>
                    </div>
                  )
                })()}
                <div className="checkpointList">
                  {filteredCheckpoints.length === 0 && (
                    <p className="cpEmpty">No checkpoints yet. Click "Checkpoint" to capture current network state.</p>
                  )}
                  {filteredCheckpoints.slice().reverse().map(cp => (
                    <div key={cp.id} className={['checkpointItem', cp.type === 'auto' ? 'cpAuto' : ''].filter(Boolean).join(' ')}>
                      <div className="cpMeta">
                        {editingCpId === cp.id
                          ? (
                            <input
                              autoFocus
                              className="cpLabelInput"
                              value={editingCpLabel}
                              onChange={e => setEditingCpLabel(e.target.value)}
                              onBlur={commitRename}
                              onKeyDown={e => {
                                if (e.key === 'Enter') commitRename()
                                if (e.key === 'Escape') { setEditingCpId(null); setEditingCpLabel('') }
                              }}
                            />
                          )
                          : (
                            <span
                              className="cpLabel cpLabelEditable"
                              title="Double-click to rename"
                              onDoubleClick={() => startRename(cp)}
                            >{cp.label}</span>
                          )
                        }
                        <span className="cpStats">{cp.nodeCount} hosts · {cp.edgeCount} edges</span>
                        {cp.reason && <span className="cpReason">{cp.reason}</span>}
                      </div>
                      <div className="cpActions">
                        {cp.id === referenceId
                          ? <span className="cpRefBadge">Reference</span>
                          : <button type="button" className="cpRefBtn" onClick={() => setReferenceId(cp.id)}>Set as Reference</button>
                        }
                        <button type="button" onClick={() => computeDiff(cp.id, 'current')}>vs Now</button>
                        <button type="button" onClick={() => {
                          if (cp.id === referenceId) setReferenceId(null)
                          setCheckpoints(prev => prev.filter(c => c.id !== cp.id))
                        }}>×</button>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="focusControls">
                  <span className="focusLabel">De-emphasize:</span>
                  {[
                    { key: 'BCAST', label: 'Broadcast / ARP' },
                    { key: 'MCAST', label: 'Multicast / mDNS' },
                  ].map(({ key, label }) => (
                    <button
                      key={key}
                      type="button"
                      className={deemphasizeGroups.has(key) ? 'active' : ''}
                      onClick={() => setDeemphasizeGroups(prev => {
                        const next = new Set(prev)
                        next.has(key) ? next.delete(key) : next.add(key)
                        return next
                      })}
                    >{label}</button>
                  ))}
                </div>
              </div>
            )}

            {/* Diff panel */}
            {!screensaverActive && activeDiff && (
              <div className="diffPanel">
                <div className="diffHeader">
                  <span className="diffTitle">Diff</span>
                  <label className="diffOnlyToggle">
                    <input type="checkbox" checked={diffMode} onChange={e => setDiffMode(e.target.checked)} />
                    Diff only
                  </label>
                  <button type="button" className="diffClearBtn" onClick={clearDiff}>Clear</button>
                </div>
                <div className="diffCards">
                  {activeDiff.result.summary.addedNodeCount > 0 &&
                    <div className="diffCard added">+{activeDiff.result.summary.addedNodeCount} hosts</div>}
                  {activeDiff.result.summary.removedNodeCount > 0 &&
                    <div className="diffCard removed">−{activeDiff.result.summary.removedNodeCount} hosts</div>}
                  {activeDiff.result.summary.addedEdgeCount > 0 &&
                    <div className="diffCard added">+{activeDiff.result.summary.addedEdgeCount} convs</div>}
                  {activeDiff.result.summary.removedEdgeCount > 0 &&
                    <div className="diffCard removed">−{activeDiff.result.summary.removedEdgeCount} convs</div>}
                  {activeDiff.result.summary.changedNodeCount > 0 &&
                    <div className="diffCard changed">{activeDiff.result.summary.changedNodeCount} changed</div>}
                </div>
                <div className="diffLegend">
                  <span className="diffLegendItem added">added</span>
                  <span className="diffLegendItem changed">changed</span>
                  <span className="diffLegendItem removed">removed</span>
                </div>
                <div className="diffDetails">
                  {activeDiff.result.addedNodes.length > 0 && (
                    <section className="diffSection">
                      <h4>+ Added Hosts</h4>
                      {activeDiff.result.addedNodes.map(n => (
                        <button key={n.ip} type="button" className="diffNodeRow added" onClick={() => setSelectedIp(n.ip)}>
                          <span className="diffIp">{n.ip}</span>
                          <span className="diffKind">{n.kind}</span>
                        </button>
                      ))}
                    </section>
                  )}
                  {activeDiff.result.removedNodes.length > 0 && (
                    <section className="diffSection">
                      <h4>− Removed Hosts</h4>
                      {activeDiff.result.removedNodes.map(n => (
                        <div key={n.ip} className="diffNodeRow removed">
                          <span className="diffIp">{n.ip}</span>
                          <span className="diffKind">{n.kind}</span>
                        </div>
                      ))}
                    </section>
                  )}
                  {activeDiff.result.changedNodes.length > 0 && (
                    <section className="diffSection">
                      <h4>Changed Hosts</h4>
                      {activeDiff.result.changedNodes.slice(0, 10).map(n => (
                        <button key={n.ip} type="button" className="diffNodeRow changed" onClick={() => setSelectedIp(n.ip)}>
                          <span className="diffIp">{n.ip}</span>
                          <span className="diffDelta">{fmtBytes(n.bytesDelta)}</span>
                          <span className="diffReasonChip">{n.reason}</span>
                        </button>
                      ))}
                    </section>
                  )}
                  {activeDiff.result.addedEdges.length > 0 && (
                    <section className="diffSection">
                      <h4>+ Added Conversations</h4>
                      {activeDiff.result.addedEdges.slice(0, 10).map((e, i) => (
                        <div key={i} className="diffEdgeRow added">
                          <span>{e.src}</span>
                          <span className="diffArrow">→</span>
                          <span>{e.dst}</span>
                          {e.isExternal && <span className="diffExtBadge">ext</span>}
                        </div>
                      ))}
                    </section>
                  )}
                  {activeDiff.result.removedEdges.length > 0 && (
                    <section className="diffSection">
                      <h4>− Removed Conversations</h4>
                      {activeDiff.result.removedEdges.slice(0, 10).map((e, i) => (
                        <div key={i} className="diffEdgeRow removed">
                          <span>{e.src}</span>
                          <span className="diffArrow">→</span>
                          <span>{e.dst}</span>
                        </div>
                      ))}
                    </section>
                  )}
                  {activeDiff.result.protocolDeltas.length > 0 && (
                    <section className="diffSection">
                      <h4>Protocol Shifts</h4>
                      {activeDiff.result.protocolDeltas.slice(0, 8).map(d => (
                        <div key={d.proto} className="diffProtoRow">
                          <span className="diffProto">{d.proto}</span>
                          <span className={d.pktsDelta > 0 ? 'diffPos' : 'diffNeg'}>
                            {d.pktsDelta > 0 ? '+' : ''}{d.pktsDelta} pkts
                          </span>
                          <span className={d.pctChange > 0 ? 'diffPos' : 'diffNeg'}>
                            {d.pctChange > 0 ? '+' : ''}{d.pctChange}%
                          </span>
                        </div>
                      ))}
                    </section>
                  )}
                </div>
              </div>
            )}

            <div ref={mountRef} className="canvasMount" />
            {diffReasonTooltip && (
              <div
                className="diffTooltip"
                style={{ left: diffReasonTooltip.x + 14, top: diffReasonTooltip.y - 10 }}
              >
                {diffReasonTooltip.text}
              </div>
            )}

            {/* Live Change Feed */}
            {!screensaverActive && (
              <div className={`changeFeedPanel${feedOpen ? ' open' : ''}`}>
                <div className="feedHeader" onClick={() => setFeedOpen(o => !o)}>
                  <span>Live Feed</span>
                  {changeFeed.length > 0 && <span className="feedCount">{changeFeed.length}</span>}
                  <span className="feedChevron">{feedOpen ? '▾' : '▸'}</span>
                </div>
                {feedOpen && (
                  <div className="feedList">
                    {changeFeed.length === 0
                      ? <div className="feedEmpty">No events yet</div>
                      : changeFeed.map(e => (
                        <button
                          key={e.id}
                          type="button"
                          className={`feedRow ${e.type}`}
                          onClick={() => e.ip && setSelectedIp(e.ip)}
                        >
                          <span className="feedTime">{fmtTs(e.ts)}</span>
                          <span className="feedReason">{e.reason}</span>
                        </button>
                      ))
                    }
                  </div>
                )}
              </div>
            )}

            {screensaverActive && (
              <div
                onClick={() => setScreensaverActive(false)}
                style={{
                  position: 'absolute', inset: 0,
                  zIndex: 9998, cursor: 'none',
                  background: 'transparent',
                }}
              />
            )}
            {pointReticle.active && (
              <div
                className={[
                  'pointReticle',
                  pointReticle.locked ? 'locked' : '',
                  pointReticle.lockProgress > 0 ? 'locking' : '',
                ].filter(Boolean).join(' ')}
                aria-hidden="true"
                style={{
                  left: `${pointReticle.x}px`,
                  top: `${pointReticle.y}px`,
                  '--lock-progress': `${Math.round(pointReticle.lockProgress * 100)}%`,
                  '--reticle-scale': reticleScale,
                }}
              />
            )}

            {!screensaverActive && analysisContent[activeTab]?.()}

            {/* Right panel — inspection drawer (node detail) or top talkers */}
            {!screensaverActive && (
              <aside className={['inspectionDrawer', (selectedIp || rightPanelOpen) ? 'open' : ''].filter(Boolean).join(' ')}>
                {selectedIp ? (
                  <>
                    <div className="inspectionHeader">
                      <span className="inspectionIp">{selectedIp}</span>
                      <button type="button" className="inspectionClose" onClick={() => setSelectedIp(null)}>×</button>
                    </div>
                    <div className="inspectionTabs">
                      {['overview','peers','protocols','packets'].map(tab => (
                        <button key={tab} type="button" className={drawerTab === tab ? 'active' : ''} onClick={() => setDrawerTab(tab)}>
                          {tab}
                        </button>
                      ))}
                    </div>
                    <div className="inspectionBody">
                      {drawerTab === 'overview' && (
                        nodeInspectionData ? (
                          <>
                            <dl className="inspectionDl">
                              <div><dt>IP</dt><dd>{selectedIp}</dd></div>
                              <div><dt>Type</dt><dd>{classifyIp(selectedIp)}</dd></div>
                              {nodeInspectionData.mac && <div><dt>MAC</dt><dd>{nodeInspectionData.mac}</dd></div>}
                              <div><dt>Bytes</dt><dd>{fmtBytes(nodeInspectionData.bytes)}</dd></div>
                              <div><dt>Packets</dt><dd>{nodeInspectionData.packets.toLocaleString()}</dd></div>
                              <div><dt>Protocols</dt><dd>{nodeInspectionData.protocols.join(', ')}</dd></div>
                            </dl>
                            <button
                              type="button"
                              className="copyFilterBtn"
                              onClick={() => navigator.clipboard?.writeText(`ip.addr == ${selectedIp}`)}
                            >
                              Copy Wireshark Filter
                            </button>
                          </>
                        ) : <p className="inspectionEmpty">No data yet.</p>
                      )}
                      {drawerTab === 'peers' && (
                        nodeInspectionData?.peers.length ? (
                          <ul className="inspectionList">
                            {nodeInspectionData.peers.slice(0, 40).map((peer, i) => (
                              <li key={i}>
                                <button type="button" onClick={() => setSelectedIp(peer.ip)}>{peer.ip}</button>
                                <span>{peer.bytes.toLocaleString()} B</span>
                              </li>
                            ))}
                          </ul>
                        ) : <p className="inspectionEmpty">No conversations yet.</p>
                      )}
                      {drawerTab === 'protocols' && (
                        nodeInspectionData?.protocols.length ? (
                          <ul className="inspectionList">
                            {nodeInspectionData.protocols.map(p => <li key={p}><span>{p}</span></li>)}
                          </ul>
                        ) : <p className="inspectionEmpty">No protocol data.</p>
                      )}
                      {drawerTab === 'packets' && (
                        nodeInspectionData?.recentPackets.length ? (
                          <ul className="inspectionList inspectionPackets">
                            {nodeInspectionData.recentPackets.map((p, i) => (
                              <li key={i}>
                                <span className="pktProto">{p.proto || 'OTHER'}</span>
                                <span>{(p.src || p.srcIp) === selectedIp ? '→' : '←'} {(p.src || p.srcIp) === selectedIp ? (p.dst || p.dstIp) : (p.src || p.srcIp)}</span>
                                <span>{p.size || 0}B</span>
                              </li>
                            ))}
                          </ul>
                        ) : <p className="inspectionEmpty">No packets yet.</p>
                      )}
                    </div>
                  </>
                ) : rightPanelOpen && timeRange && windowAnalysis ? (
                  /* Window Summary — shown when a time range is selected */
                  <div className="windowSummary">
                    <div className="windowSummaryHeader">
                      <span className="windowSummaryTitle">
                        {windowCompareActive ? 'Top Changes' : 'Window Summary'}
                        <span className="windowDuration"> ({formatWindowDuration(timeRange)})</span>
                      </span>
                      <button type="button" className="inspectionClose" onClick={() => { setTimeRange(null); setWindowCompareActive(false) }}>×</button>
                    </div>
                    <div className="windowStatRow">
                      <span>{windowAnalysis.endpoints.length} hosts</span>
                      <span>{fmtBytes(windowAnalysis.totalBytes)}</span>
                      {windowDiffResult && <span className="windowNewCount">+{windowDiffResult.summary.addedNodeCount} new</span>}
                    </div>
                    <div className="windowSection">
                      <div className="windowSectionTitle">{windowCompareActive && windowDiffResult ? 'Top Changes' : 'Top Talkers'}</div>
                      {(windowCompareActive && windowDiffResult?.changedNodes.length > 0
                        ? windowDiffResult.changedNodes.slice(0, 6)
                        : windowAnalysis.endpoints.slice(0, 6)
                      ).map(item => {
                        const ip = item.ip
                        const isNew = windowDiffResult?.addedNodes.some(n => n.ip === ip)
                        const isChanged = !isNew && windowDiffResult?.changedNodes.some(n => n.ip === ip)
                        return (
                          <button key={ip} type="button" className="windowNodeRow" onClick={() => setSelectedIp(ip)}>
                            <span className="windowNodeIp">{ip}</span>
                            <span className="windowNodeBytes">{fmtBytes(item.bytes ?? item.bytesDelta ?? 0)}</span>
                            {isNew && <span className="windowBadge new">new</span>}
                            {isChanged && <span className="windowBadge chg">↑</span>}
                          </button>
                        )
                      })}
                    </div>
                    {windowDiffResult?.addedNodes.filter(n => n.kind === 'external').length > 0 && (
                      <div className="windowSection">
                        <div className="windowSectionTitle">New External</div>
                        {windowDiffResult.addedNodes.filter(n => n.kind === 'external').slice(0, 4).map(n => (
                          <button key={n.ip} type="button" className="windowNodeRow" onClick={() => setSelectedIp(n.ip)}>
                            <span className="windowNodeIp">{n.ip}</span>
                            <span className="windowBadge ext">ext</span>
                          </button>
                        ))}
                      </div>
                    )}
                    <div className="windowSection">
                      <div className="windowSectionTitle">Protocols</div>
                      {windowAnalysis.protocols.slice(0, 5).map(p => {
                        const delta = windowDiffResult?.protocolDeltas.find(d => d.proto === p.proto)
                        return (
                          <div key={p.proto} className="windowProtoRow">
                            <span>{p.proto}</span>
                            <span>{p.packets} pkts</span>
                            {delta && Math.abs(delta.pctChange) > 10 && (
                              <span className="windowBadge chg">{delta.pctChange > 0 ? '+' : ''}{delta.pctChange}%</span>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ) : rightPanelOpen ? (
                  /* Top Talkers view (default when no node selected) */
                  <>
                    <div className="inspectionHeader">
                      <span className="inspectionIp" style={{ color: 'var(--text-dim)' }}>Top Talkers</span>
                      <button type="button" className="inspectionClose" onClick={() => setRightPanelOpen(false)}>×</button>
                    </div>
                    <div className="inspectionBody">
                      {trafficAnalysis.endpoints.length === 0 ? (
                        <p className="inspectionEmpty">No traffic yet.</p>
                      ) : (
                        <ul className="inspectionList">
                          {trafficAnalysis.endpoints.slice(0, 20).map((ep, i) => (
                            <li key={ep.ip}>
                              <span style={{ color: 'var(--text-dimmer)', minWidth: 20, flexShrink: 0 }}>#{i + 1}</span>
                              <button type="button" onClick={() => setSelectedIp(ep.ip)}>{ep.ip}</button>
                              <span>{fmtBytes(ep.bytes)}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </>
                ) : null}
              </aside>
            )}

            <section className="graphToolbar liveGraphToolbar" aria-label="Graph controls" style={{ display: screensaverActive ? 'none' : undefined }}>
              <button
                type="button"
                style={{ color: gesturesEnabled ? '#4af0b4' : undefined }}
                onClick={() => setGesturesEnabled(e => !e)}
              >
                {gesturesEnabled ? '✋ ON' : '✋ Gestures'}
              </button>
              <button
                type="button"
                style={{ color: rightPanelOpen && !selectedIp ? 'var(--accent)' : undefined }}
                onClick={() => { setRightPanelOpen(v => !v); setSelectedIp(null) }}
              >
                {rightPanelOpen && !selectedIp ? 'Hide Panel' : 'Top Talkers'}
              </button>
            </section>

            {selectedIp && (
              <button className="wholeNetworkButton" type="button" onClick={() => setSelectedIp(null)}>
                Whole network
              </button>
            )}

            {/* Bottom timeline strip */}
            {!screensaverActive && (
              <div className="timelineStrip">
                {(() => {
                  const bounds = timelineBounds ?? (activeSource === 'replay' && replayMeta ? { min: 0, max: replayMeta.duration } : null)
                  if (!bounds) return null
                  const span     = bounds.max - bounds.min
                  const leftPct  = timeRange ? ((timeRange.start - bounds.min) / span) * 100 : null
                  const rightPct = timeRange ? ((timeRange.end   - bounds.min) / span) * 100 : null
                  const scrubberT = activeSource === 'replay'
                    ? replayTime
                    : (liveTime ?? bounds.max ?? null)
                  const playPct = scrubberT != null && span > 0
                    ? Math.max(0, Math.min(100, ((scrubberT - bounds.min) / span) * 100))
                    : null
                  const rel = t => t - (activeSource === 'replay' ? 0 : bounds.min)

                  return (
                    <div className="utlBody">
                      <span className="utlTime">
                        {timeRange ? formatReplayTime(rel(timeRange.start)) : (scrubberT != null ? formatReplayTime(rel(scrubberT)) : '')}
                      </span>
                      <div
                        className="utlTrack"
                        ref={trackRef}
                        onPointerDown={handleTimelinePointerDown}
                        onPointerMove={handleTimelinePointerMove}
                        onPointerUp={handleTimelinePointerUp}
                        onPointerCancel={handleTimelinePointerUp}
                      >
                        {leftPct  != null && <div className="utlDimLeft"  style={{ width: `${leftPct}%` }} />}
                        {rightPct != null && <div className="utlDimRight" style={{ left: `${rightPct}%`, width: `${100 - rightPct}%` }} />}
                        {leftPct != null && rightPct != null && (
                          <div className="utlWindowFill" style={{ left: `${leftPct}%`, width: `${rightPct - leftPct}%` }} />
                        )}
                        {leftPct  != null && <div className="utlHandle utlHandleLeft"  style={{ left: `${leftPct}%` }} />}
                        {rightPct != null && <div className="utlHandle utlHandleRight" style={{ left: `${rightPct}%` }} />}
                        {playPct  != null && <div className="utlPlayhead" style={{ left: `${playPct}%` }} />}
                      </div>
                      <span className="utlTime">
                        {timeRange ? formatReplayTime(rel(timeRange.end)) : formatReplayTime(span)}
                      </span>
                      {timeRange && (
                        <>
                          <button type="button" className="timelineBtn"
                            onClick={() => { setTimeRange(null); setWindowCompareActive(false) }}>Clear</button>
                          {hasBaseWindow
                            ? <button type="button"
                                className={`timelineBtn${windowCompareActive ? ' active' : ''}`}
                                onClick={() => setWindowCompareActive(v => !v)}>
                                {windowCompareActive ? 'Comparing' : 'Compare'}
                              </button>
                            : <span className="timelineBtnDisabled">Select window</span>
                          }
                        </>
                      )}
                      {activeSource === 'live' && liveTime !== null && !timeRange && (
                        <button type="button" className="timelineBtn active" onClick={() => setLiveTime(null)}>
                          ▶ Live
                        </button>
                      )}
                    </div>
                  )
                })()}
              </div>
            )}
          </section>
        </div>
    </main>
  )
}
