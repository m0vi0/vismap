import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import HeroAsciiOne from './components/ui/hero-ascii-one.jsx'
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
const ORBIT_TARGET = new THREE.Vector3(0, 0, -140)
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
  stats: 'Whole Network Stats',
  conversations: 'Conversations',
  endpoints: 'Endpoints',
  protocols: 'Protocol Hierarchy',
  io: 'I/O Graphs',
}

const ANALYSIS_TABS = new Set(['stats', 'conversations', 'endpoints', 'protocols', 'io'])

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

function parseDisplayFilter(expression) {
  const raw = expression.trim()
  if (!raw) return { raw, type: 'all' }

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

function clusterAnchor(ip) {
  const hash = hashString(subnetKey(ip))
  const theta = ((hash & 0xffff) / 0xffff) * Math.PI * 2
  const z = (((hash >>> 16) & 0xffff) / 0xffff) * 2 - 1
  const radius = 135
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
  const orbitStateRef = useRef({
    isPointerDown: false, isDrag: false, lastX: 0, lastY: 0,
    theta: Math.PI * 0.18, phi: Math.PI * 0.28, radius: 820,
    panX: 0, panY: 0, panZ: 0,
    recenterPan: false,
    target: ORBIT_TARGET.clone(),
  })
  const applyOrbitRef = useRef(null)
  const layoutSpreadRef = useRef({ value: 1, target: 1 })
  const ingestPacketRef = useRef(null)
  const resetGraphRef = useRef(null)
  const snapshotGraphRef = useRef(null)
  const rebuildGraphRef = useRef(null)

  const [gesturesEnabled, setGesturesEnabled] = useState(true)
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
  const [activeTab, setActiveTab] = useState('live')
  const [menuCollapsed, setMenuCollapsed] = useState(false)
  const [appMode, setAppMode] = useState('live')
  const [activeSource, setActiveSource] = useState('live')
  const [filterInput, setFilterInput] = useState('')
  const [activeFilter, setActiveFilter] = useState({ raw: '', type: 'all' })
  const [filterError, setFilterError] = useState('')
  const [cameraZoom, setCameraZoom] = useState(DEFAULT_CAMERA_ZOOM)
  const [showLabels, setShowLabels] = useState(true)
  const [labelMode, setLabelMode] = useState('resolvedIp')
  const [status, setStatus] = useState('connecting')
  const [captureMessage, setCaptureMessage] = useState('')
  const [captureInterface, setCaptureInterface] = useState('en0')
  const [selectedIp, setSelectedIp] = useState(null)
  const [selectedConversationKey, setSelectedConversationKey] = useState(null)
  const [selectedProtocol, setSelectedProtocol] = useState(null)
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

  const sourcePackets = useMemo(() => {
    if (activeSource === 'replay') return replayPackets.slice(Math.max(0, replayIndex - ANALYSIS_PACKET_WINDOW), replayIndex)
    return livePackets.slice(-ANALYSIS_PACKET_WINDOW)
  }, [activeSource, livePackets, replayIndex, replayPackets])

  const filteredPackets = useMemo(
    () => sourcePackets.filter((packet) => packetMatchesFilter(packet, activeFilter)),
    [activeFilter, sourcePackets],
  )

  const analysisActive = ANALYSIS_TABS.has(activeTab)

  const selectedPacket = useMemo(
    () => analysisActive ? filteredPackets.find((packet) => packet.id === selectedPacketId) || null : null,
    [analysisActive, filteredPackets, selectedPacketId],
  )

  const trafficAnalysis = analysisSnapshot
  const replayGraphBucket = activeSource === 'replay' ? Math.floor(replayTime * 8) : 0

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

  useEffect(() => {
    if (!analysisActive) {
      if (analysisSnapshotTimerRef.current !== null) {
        window.clearTimeout(analysisSnapshotTimerRef.current)
        analysisSnapshotTimerRef.current = null
      }
      return undefined
    }

    if (analysisSnapshotTimerRef.current !== null) return undefined

    analysisSnapshotTimerRef.current = window.setTimeout(() => {
      analysisSnapshotTimerRef.current = null
      setAnalysisSnapshot(buildTrafficAnalysis(filteredPacketsRef.current, replayMeta, conversationSort))
    }, ANALYSIS_SNAPSHOT_MS)

    return undefined
  }, [analysisActive, conversationSort, filteredPackets, replayMeta])

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
    const mount = mountRef.current
    const nodeStore = nodesRef.current
    const edgeStore = edgesRef.current
    const packetStore = packetsRef.current
    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x050505)

    const camera = new THREE.PerspectiveCamera(55, mount.clientWidth / mount.clientHeight, 1, 4000)
    camera.position.set(0, 620, 520)
    camera.lookAt(0, 0, 0)
    cameraRef.current = camera

    function applyOrbit() {
      const target = orbitStateRef.current.target
      const x = orbitStateRef.current.radius * Math.sin(orbitStateRef.current.phi) * Math.sin(orbitStateRef.current.theta)
      const y = orbitStateRef.current.radius * Math.cos(orbitStateRef.current.phi)
      const z = orbitStateRef.current.radius * Math.sin(orbitStateRef.current.phi) * Math.cos(orbitStateRef.current.theta)
      camera.position.set(target.x + x, target.y + y, target.z + z)
      camera.lookAt(target)
    }
    applyOrbitRef.current = applyOrbit
    orbitStateRef.current.target = ORBIT_TARGET.clone()
    applyOrbit()

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.outputColorSpace = THREE.SRGBColorSpace
    mount.appendChild(renderer.domElement)

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
    const pointer = new THREE.Vector2()

    function updateOrbitTarget() {
      let count = 0
      const center = new THREE.Vector3()
      const orbit = orbitStateRef.current

      orbit.panX = THREE.MathUtils.clamp(orbit.panX || 0, -PAN_BOUND, PAN_BOUND)
      orbit.panY = THREE.MathUtils.clamp(orbit.panY || 0, -PAN_BOUND, PAN_BOUND)
      orbit.panZ = THREE.MathUtils.clamp(orbit.panZ || 0, -PAN_BOUND, PAN_BOUND)

      if (orbit.recenterPan) {
        orbit.panX = THREE.MathUtils.lerp(orbit.panX, 0, 0.055)
        orbit.panY = THREE.MathUtils.lerp(orbit.panY, 0, 0.055)
        orbit.panZ = THREE.MathUtils.lerp(orbit.panZ, 0, 0.055)
        if (Math.abs(orbit.panX) + Math.abs(orbit.panY) + Math.abs(orbit.panZ) < 0.6) {
          orbit.panX = 0
          orbit.panY = 0
          orbit.panZ = 0
          orbit.recenterPan = false
        }
      }

      nodeStore.forEach((node) => {
        if (!node.group.visible) return
        center.x += node.x
        center.y += node.y
        center.z += node.z
        count += 1
      })

      if (!count) {
        orbit.target.lerp(new THREE.Vector3(
          ORBIT_TARGET.x + (orbit.panX || 0),
          ORBIT_TARGET.y + (orbit.panY || 0),
          ORBIT_TARGET.z + (orbit.panZ || 0),
        ), 0.04)
        return
      }

      center.multiplyScalar(1 / count)
      center.x += orbit.panX || 0
      center.y += orbit.panY || 0
      center.z += orbit.panZ || 0
      orbit.target.lerp(center, 0.06)
    }

    function snapshotState() {
      // Keep this hook available for summary packets without forcing React renders on the graph hot path.
    }

    function rebuildGraph(packets) {
      clearGraph()
      packets.forEach((packet) => ingestPacket(packet))
      snapshotState()
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

    function clearGraph() {
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
      })
      nodeStore.clear()
      setSelectedIp(null)
      pointTargetRef.current = { active: false, ip: null, x: 0, y: 0 }
      setPointReticle((current) => ({ ...current, active: false, locked: false }))
      orbitStateRef.current.panX = 0
      orbitStateRef.current.panY = 0
      orbitStateRef.current.panZ = 0
      orbitStateRef.current.recenterPan = false
      layoutSpreadRef.current.value = 1
      layoutSpreadRef.current.target = 1
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

      scene.add(group)

      const node = {
        ip,
        group,
        mesh,
        label,
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
        clusterAnchor: clusterAnchor(ip),
        mac: '',
        labelText: ip,
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
          const spacing = collisionNodeRadius(a) + collisionNodeRadius(b) + 34 + 58 * spreadForce
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
      const srcNode = ensureNode(src)
      const dstNode = ensureNode(dst)
      const edge = ensureEdge(src, dst)
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
        refreshNodeLabel(node)
        node.group.position.set(node.x, node.y, node.z)
        node.mesh.scale.lerp(new THREE.Vector3(scale + pulse, scale + pulse, scale + pulse), 0.18)
        node.mesh.material.opacity = THREE.MathUtils.lerp(node.mesh.material.opacity, visibleWeight, 0.12)
        node.label.visible = labelsEnabled
        node.label.material.opacity = THREE.MathUtils.lerp(
          node.label.material.opacity,
          !labelsEnabled ? 0 : hasFocus && depth === undefined ? 0.12 : Math.max(visibleWeight, labelOpacityFloor),
          0.14,
        )
        node.label.position.y = 22 + scale * 7
        node.label.scale.lerp(new THREE.Vector3(150 * labelScale, 38 * labelScale, 1), 0.18)
        node.recentBytes *= 0.91
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
        const baseOpacity = focusedEdge ? (chattyness > 0 ? 0.28 : 0.18) : 0.06
        const activeOpacity = focusedEdge ? 0.96 : 0.24
        const targetOpacity = baseOpacity + chattyness * (activeOpacity - baseOpacity)
        const positions = edge.mesh.geometry.attributes.position
        positions.setXYZ(0, a.x, a.y, a.z)
        positions.setXYZ(1, b.x, b.y, b.z)
        positions.needsUpdate = true
        edge.mesh.geometry.computeBoundingSphere()
        edge.mesh.material.opacity = THREE.MathUtils.lerp(edge.mesh.material.opacity, targetOpacity, 0.12)
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
    snapshotGraphRef.current = snapshotState
    rebuildGraphRef.current = rebuildGraph

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
      updateOrbitTarget()
      applyOrbit()

      nodeStore.forEach((node) => {
        node.label.quaternion.copy(camera.quaternion)
      })

      renderer.render(scene, camera)
    }

    function handlePointerDown(event) {
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
      } else {
        // start drag — do NOT clear selection here
        orbitStateRef.current.isPointerDown = true
        orbitStateRef.current.isDrag = false
        orbitStateRef.current.lastX = event.clientX
        orbitStateRef.current.lastY = event.clientY
      }
    }

    function handlePointerMove(event) {
      const orbit = orbitStateRef.current
      if (!orbit.isPointerDown) return
      const dx = event.clientX - orbit.lastX
      const dy = event.clientY - orbit.lastY
      orbit.isDrag = true

      if (event.shiftKey) {
        const panSpeed = orbit.radius * 0.001
        orbit.target.x -= dx * panSpeed
        orbit.target.y += dy * panSpeed
      } else {
        orbit.theta -= dx * 0.006
        orbit.phi = THREE.MathUtils.clamp(orbit.phi + dy * 0.006, 0.08, Math.PI - 0.08)
      }

      orbit.lastX = event.clientX
      orbit.lastY = event.clientY
      applyOrbit()
    }

    function handlePointerUp(event) {
      const wasDrag = orbitStateRef.current.isDrag
      orbitStateRef.current.isPointerDown = false
      orbitStateRef.current.isDrag = false

      if (!wasDrag && selectedIpRef.current) {
        const bounds = renderer.domElement.getBoundingClientRect()
        pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1
        pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1
        raycaster.setFromCamera(pointer, camera)
        const meshes = [...nodeStore.values()].filter(n => n.group.visible).map(n => n.mesh)
        const hit = raycaster.intersectObjects(meshes, false)[0]
        if (!hit) setSelectedIp(null)
      }
    }
    function handleWheel(event) {
      event.preventDefault()
      orbitStateRef.current.radius = THREE.MathUtils.clamp(orbitStateRef.current.radius + event.deltaY * 0.8, 200, 2200)
      applyOrbit()
    }

    function handleResize() {
      camera.aspect = mount.clientWidth / mount.clientHeight
      camera.updateProjectionMatrix()
      renderer.setSize(mount.clientWidth, mount.clientHeight)
    }
    renderer.domElement.addEventListener('pointerdown', handlePointerDown)
    renderer.domElement.addEventListener('pointermove', handlePointerMove)
    renderer.domElement.addEventListener('pointerup', handlePointerUp)
    renderer.domElement.addEventListener('pointerleave', handlePointerUp)
    renderer.domElement.addEventListener('wheel', handleWheel, { passive: false })
    window.addEventListener('resize', handleResize)
    animate()

    const ws = new WebSocket(WS_URL)
    websocketRef.current = ws
    ws.addEventListener('open', () => {
      setStatus('ready')
    })

    ws.addEventListener('message', (event) => {
      const data = JSON.parse(event.data)
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
        if (appModeRef.current === 'live' && activeSourceRef.current === 'live' && packetMatchesFilter(packet, activeFilterRef.current)) {
          ingestPacket(packet)
        }
      }
      if (data.type === 'nodes' && appModeRef.current === 'live') applyNodeSummary(data.nodes || [])
      if (data.type === 'capture_status') {
        if (data.iface && data.iface !== 'default interface') setCaptureInterface(data.iface)
        setCaptureMessage(data.message || '')
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
      ws.close()
      cancelAnimationFrame(frameRef.current)
      window.removeEventListener('resize', handleResize)
      renderer.domElement.removeEventListener('pointermove', handlePointerMove)
      renderer.domElement.removeEventListener('pointerup', handlePointerUp)
      renderer.domElement.removeEventListener('pointerleave', handlePointerUp)
      renderer.domElement.removeEventListener('pointerdown', handlePointerDown)
      renderer.domElement.removeEventListener('wheel', handleWheel)

      nodeStore.forEach((node) => {
        scene.remove(node.group)
        node.mesh.material.dispose()
        node.label.material.map.dispose()
        node.label.material.dispose()
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

    const orbitRef = orbitStateRef
    const orbitApply = applyOrbitRef
    const cam = cameraRef
    const nodes = nodesRef

    import('./useHandGestures.js').then((module) => {
      const init = module.useHandGestures({
        orbitStateRef: orbitRef,
        applyOrbitRef: orbitApply,
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
    if (!rebuildGraphRef.current) return
    if (activeSource === 'replay') {
      rebuildGraphRef.current(filteredPacketsRef.current)
      return
    }

    if (graphRebuildTimerRef.current !== null) return
    graphRebuildTimerRef.current = window.setTimeout(() => {
      graphRebuildTimerRef.current = null
      rebuildGraphRef.current?.(filteredPacketsRef.current)
    }, LIVE_GRAPH_REBUILD_MS)
  }, [activeFilter, activeSource, replayGraphBucket])

  useEffect(() => {
    if (!analysisActive) return
    if (selectedPacketId && !filteredPackets.some((packet) => packet.id === selectedPacketId)) {
      setSelectedPacketId(null)
    }
  }, [analysisActive, filteredPackets, selectedPacketId])

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

  function applyDisplayFilter(event) {
    event.preventDefault()
    try {
      const nextFilter = parseDisplayFilter(filterInput)
      setActiveFilter(nextFilter)
      setFilterError('')
      setSelectedConversationKey(null)
      setSelectedProtocol(nextFilter.type === 'protocol' ? nextFilter.value : null)
    } catch (error) {
      setFilterError(error instanceof Error ? error.message : 'Unsupported display filter.')
    }
  }

  function clearDisplayFilter() {
    setFilterInput('')
    setActiveFilter({ raw: '', type: 'all' })
    setFilterError('')
    setSelectedProtocol(null)
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
      setReplayState(parsed.packets.length ? 'paused' : 'idle')
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

  const needsCapturePermission = status === 'ready' || status === 'capture_error'
  const currentThroughput = trafficAnalysis.throughput
  const packetRows = analysisActive ? filteredPackets.slice(-TABLE_ROW_LIMIT).reverse() : []
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
  const showLiveWorkspaceControls = activeTab === 'live'

  const analysisContent = {
    live: () => (
      <section className="analysisTab liveAnalysis">
        <div className="analysisHeader">
          <div>
            <p>Capture Source</p>
            <h2>{activeSource === 'live' ? 'Live Capture' : 'PCAP Replay'}</h2>
          </div>
          <div className="sourceSwitch" aria-label="Input source">
            <button className={activeSource === 'live' ? 'active' : ''} type="button" onClick={() => { setActiveSource('live'); setAppMode('live'); setReplayState('idle') }}>Live</button>
            <button className={activeSource === 'replay' ? 'active' : ''} type="button" onClick={() => { setActiveSource('replay'); setAppMode('replay') }}>PCAP Replay</button>
          </div>
        </div>

        {activeSource === 'live' ? (
          <div className="sourcePanel">
            <label className="fieldLabel" htmlFor="capture-interface">Interface</label>
            <input id="capture-interface" value={captureInterface} onChange={(event) => setCaptureInterface(event.target.value)} placeholder="en0, eth0, wlan0" />
            <div className="exampleChips" aria-label="Interface examples">
              {['en0', 'eth0', 'wlan0'].map((iface) => (
                <button type="button" key={iface} onClick={() => setCaptureInterface(iface)}>{iface}</button>
              ))}
            </div>
            <dl className="liveStatus">
              <div><dt>WebSocket</dt><dd>{status}</dd></div>
              <div><dt>Packets</dt><dd>{livePackets.length.toLocaleString()}</dd></div>
              <div><dt>Filtered</dt><dd>{filteredPackets.length.toLocaleString()}</dd></div>
            </dl>
            {captureMessage && <p className="permissionError">{captureMessage}</p>}
            <button className="primaryAction" type="button" onClick={requestCapture}>
              {needsCapturePermission ? 'Start live capture' : 'Restart live view'}
            </button>
          </div>
        ) : (
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
                <input className="timeline" type="range" min="0" max={Math.max(replayMeta.duration, 0.1)} step="0.1" value={Math.min(replayTime, Math.max(replayMeta.duration, 0.1))} onChange={(event) => scrubReplay(event.target.value)} />
                <p className="noteText">{replayIndex.toLocaleString()} of {replayPackets.length.toLocaleString()} packets replayed.</p>
              </>
            )}
          </div>
        )}
      </section>
    ),
    stats: () => (
      <section className="analysisTab">
        <div className="analysisHeader"><p>Whole Network</p><h2>Filtered network summary</h2></div>
        <div className="metricGrid">
          <div><span>Hosts</span><strong>{trafficAnalysis.endpoints.length.toLocaleString()}</strong></div>
          <div><span>Links</span><strong>{trafficAnalysis.conversations.length.toLocaleString()}</strong></div>
          <div><span>Total Data</span><strong>{byteLabel(filteredPackets.reduce((total, packet) => total + packet.size, 0))}</strong></div>
          <div><span>Throughput</span><strong>{byteLabel(currentThroughput)}/s</strong></div>
        </div>
        <div className="analysisSplit">
          <section><h3>Top Talkers</h3>{trafficAnalysis.endpoints.slice(0, 8).map((endpoint) => <button className="dataRow" key={endpoint.ip} type="button" onClick={() => setSelectedIp(endpoint.ip)}><span>{endpoint.ip}</span><strong>{byteLabel(endpoint.bytes)}</strong></button>)}</section>
          <section><h3>Protocol Distribution</h3>{trafficAnalysis.protocols.map((protocol) => <button className="dataRow" key={protocol.proto} type="button" onClick={() => { setSelectedProtocol(protocol.proto); setFilterInput(protocol.proto.toLowerCase()); setActiveFilter(parseDisplayFilter(protocol.proto.toLowerCase())) }}><span>{protocol.proto}</span><strong>{Math.round((protocol.bytes / protocolTotalBytes) * 100)}%</strong></button>)}</section>
        </div>
      </section>
    ),
    conversations: () => (
      <section className="analysisTab">
        <div className="analysisHeader"><p>Conversations</p><h2>Communication pairs</h2></div>
        <div className="dataTable sixCol">{['Source', 'Destination', 'Protocol', 'Packets', 'Bytes', 'Rate'].map((heading) => <strong key={heading}>{heading}</strong>)}{trafficAnalysis.conversations.slice(0, LARGE_TABLE_ROW_LIMIT).map((conversation) => <button className={conversation.key === selectedConversationKey ? 'selected tableRow' : 'tableRow'} key={conversation.key} type="button" onClick={() => { setSelectedConversationKey(conversation.key); setSelectedIp(conversation.src); pointTargetRef.current = { active: true, ip: conversation.src, x: 0, y: 0 } }}><span>{conversation.src}</span><span>{conversation.dst}</span><span>{conversation.proto}</span><span>{conversation.packets.toLocaleString()}</span><span>{byteLabel(conversation.bytes)}</span><span>{byteLabel(conversation.rate)}/s</span></button>)}</div>
      </section>
    ),
    endpoints: () => (
      <section className="analysisTab">
        <div className="analysisHeader"><p>Endpoints</p><h2>Hosts and devices</h2></div>
        <div className="dataTable sixCol">{['Endpoint', 'MAC', 'Packets', 'Bytes', 'Inbound', 'Protocols'].map((heading) => <strong key={heading}>{heading}</strong>)}{trafficAnalysis.endpoints.slice(0, LARGE_TABLE_ROW_LIMIT).map((endpoint) => <button className={endpoint.ip === selectedIp ? 'selected tableRow' : 'tableRow'} key={endpoint.ip} type="button" onClick={() => setSelectedIp(endpoint.ip)}><span>{endpoint.ip}</span><span>{endpoint.mac || '-'}</span><span>{endpoint.packets.toLocaleString()}</span><span>{byteLabel(endpoint.bytes)}</span><span>{byteLabel(endpoint.bytes)}</span><span>{endpoint.protocols || '-'}</span></button>)}</div>
      </section>
    ),
    protocols: () => (
      <section className="analysisTab">
        <div className="analysisHeader"><p>Protocol Hierarchy</p><h2>Observed protocol breakdown</h2></div>
        <div className="protocolTree">{trafficAnalysis.protocols.map((protocol) => <button className={selectedProtocol === protocol.proto ? 'selected protocolNode' : 'protocolNode'} key={protocol.proto} type="button" onClick={() => { setSelectedProtocol(protocol.proto); setFilterInput(protocol.proto.toLowerCase()); setActiveFilter(parseDisplayFilter(protocol.proto.toLowerCase())) }}><span><i style={{ background: PROTOCOLS[protocol.proto]?.css || PROTOCOLS.OTHER.css }} />Frame / {protocol.proto}</span><strong>{protocol.packets.toLocaleString()} pkts · {byteLabel(protocol.bytes)} · {Math.round((protocol.bytes / protocolTotalBytes) * 100)}%</strong></button>)}</div>
      </section>
    ),
    io: () => (
      <section className="analysisTab">
        <div className="analysisHeader"><p>I/O Graphs</p><h2>Traffic over time</h2></div>
        <div className="wideTimeline">{trafficAnalysis.timelineBuckets.map((bytes, index) => <i key={`${index}-${bytes}`} style={{ height: `${Math.max(4, (bytes / trafficAnalysis.maxBucket) * 180)}px` }} title={byteLabel(bytes)} />)}</div>
      </section>
    ),
  }

  return (
    <main className="appShell">
      <HeroAsciiOne>
        <div className={menuCollapsed ? 'appFrame menuCollapsed' : 'appFrame'}>
          <nav className="appMenu" aria-label="PacMap menu">
            <div className="appMenuBrand">
              <div>
                <strong>pacmap</strong>
                <span>{status}</span>
              </div>
              <button
                className="menuCollapseButton"
                type="button"
                onClick={() => setMenuCollapsed((collapsed) => !collapsed)}
                aria-label={menuCollapsed ? 'Expand menu' : 'Collapse menu'}
                title={menuCollapsed ? 'Expand menu' : 'Collapse menu'}
              >
                {menuCollapsed ? '>' : '<'}
              </button>
            </div>
            <div className="appMenuItems">
              {Object.entries(TABS).map(([tab, label]) => (
                <button
                  className={activeTab === tab ? 'appMenuItem active' : 'appMenuItem'}
                  key={tab}
                  type="button"
                  onClick={() => {
                    setActiveTab(tab)
                  }}
                  title={label}
                >
                  <span className="appMenuShort" aria-hidden="true">
                    {label.split(' ').map((word) => word[0]).join('').slice(0, 2)}
                  </span>
                  <span className="appMenuFull">{label}</span>
                </button>
              ))}
            </div>
          </nav>

          <section
            className={activeTab === 'live' ? 'viewport liveViewport' : 'viewport analysisViewport'}
            aria-label={`${TABS[activeTab]} packet map`}
          >
            {showLiveWorkspaceControls && (
              <form className="trafficFilterBar" onSubmit={applyDisplayFilter}>
                <span>Display Filter</span>
                <input value={filterInput} onChange={(event) => setFilterInput(event.target.value)} placeholder="tcp.port == 443" />
                <button type="submit">Apply</button>
                <button type="button" onClick={clearDisplayFilter}>Clear</button>
                {filterError && <p className="filterError">{filterError}</p>}
              </form>
            )}
            <div ref={mountRef} className="canvasMount" />
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

            {analysisContent[activeTab]?.()}

            <section className={showLiveWorkspaceControls ? 'graphToolbar liveGraphToolbar' : 'graphToolbar'} aria-label="Graph controls">
              {!showLiveWorkspaceControls && (
                <>
                  <button type="button" onClick={() => setCameraZoom((zoom) => clampZoom(zoom + 0.2))}>
                    Zoom in
                  </button>
                  <button type="button" onClick={() => setCameraZoom((zoom) => clampZoom(zoom - 0.2))}>
                    Zoom out
                  </button>
                  <button type="button" onClick={() => setCameraZoom(DEFAULT_CAMERA_ZOOM)}>
                    Reset zoom
                  </button>
                  <select value={labelMode} onChange={(event) => setLabelMode(event.target.value)} aria-label="Node labels">
                    {Object.entries(LABEL_MODES).map(([mode, label]) => (
                      <option key={mode} value={mode}>
                        {label}
                      </option>
                    ))}
                  </select>
                </>
              )}
              <button
                type="button"
                style={{ color: gesturesEnabled ? '#4af0b4' : undefined }}
                onClick={() => setGesturesEnabled(e => !e)}
              >
                {gesturesEnabled ? '✋ ON' : '✋ Gestures'}
              </button>
              {!showLiveWorkspaceControls && <span>{Math.round(cameraZoom * 100)}%</span>}
            </section>

            {selectedIp && activeTab !== 'live' && (
              <button className="wholeNetworkButton" type="button" onClick={() => setSelectedIp(null)}>
                Whole network
              </button>
            )}
            {analysisActive && (
              <section className="packetInspector" aria-label="Packet inspection">
                <div className="inspectorPane packetList">
                  <h3>Packet List</h3>
                  <div className="packetTable">
                    {['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'].map((heading) => <strong key={heading}>{heading}</strong>)}
                    {packetRows.map((packet) => (
                      <button
                        className={packet.id === selectedPacketId ? 'selected tableRow' : 'tableRow'}
                        key={packet.id}
                        type="button"
                        onClick={() => {
                          setSelectedPacketId(packet.id)
                          setSelectedIp(packet.src || packet.srcIp)
                        }}
                      >
                        <span>{new Date((packet.timestamp || 0) * 1000).toLocaleTimeString()}</span>
                        <span>{packet.src || packet.srcIp}</span>
                        <span>{packet.dst || packet.dstIp}</span>
                        <span>{packet.proto}</span>
                        <span>{packet.size}</span>
                        <span>{packetInfo(packet)}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </section>
            )}
          </section>
        </div>
      </HeroAsciiOne>
    </main>
  )
}
