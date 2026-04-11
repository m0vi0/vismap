import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import HeroAsciiOne from './components/ui/hero-ascii-one.jsx'
import './App.css'

const WS_URL = 'ws://127.0.0.1:8765'
const MAX_PACKET_PARTICLES = 420
const NODE_LIMIT = 18
const FOCUS_RING_RADIUS = 92
const FOCUS_RING_MAX_RADIUS = 360
const NETWORK_RING_RADII = [0, 112, 205, 305]
const NETWORK_RING_MAX_RADII = [0, 210, 380, 560]
const NETWORK_RING_PADDING = 1.22
const NETWORK_RING_SEPARATION = 92
const NODE_RING_GAP = 18
const MIN_NODE_SCALE = 0.24
const REPLAY_TICK_MS = 40
const MIN_CAMERA_ZOOM = 0.55
const MAX_CAMERA_ZOOM = 2.5
const DEFAULT_CAMERA_ZOOM = 1

const PROTOCOLS = {
  TCP: { color: 0x60a5fa, css: '#60a5fa', label: 'TCP' },
  UDP: { color: 0x34d399, css: '#34d399', label: 'UDP' },
  DNS: { color: 0xfacc15, css: '#facc15', label: 'DNS' },
  ARP: { color: 0xfb7185, css: '#fb7185', label: 'ARP' },
  OTHER: { color: 0xc084fc, css: '#c084fc', label: 'Other' },
}

const TABS = {
  live: 'Live Capture',
  replay: 'Replay PCAP',
  instructions: 'Instructions',
}

const LABEL_MODES = {
  resolvedIp: 'Resolved IP',
  rawIp: 'Raw IP',
  rawMac: 'MAC',
  resolvedMac: 'Resolved MAC',
  off: 'Labels off',
}

const LINKTYPE_NAMES = {
  0: 'BSD loopback',
  1: 'Ethernet',
  101: 'Raw IP',
  113: 'Linux cooked v1',
  276: 'Linux cooked v2',
}

const MODE_COPY = {
  live: {
    title: 'Live Capture',
    body: 'Inspect what is happening right now. A local terminal process captures packets and streams them into this map.',
  },
  replay: {
    title: 'Replay PCAP',
    body: 'Inspect a saved capture over time. Upload a .pcap or .pcapng file and replay the packet flow here.',
  },
  instructions: {
    title: 'Instructions',
    body: 'Use PacMap as a packet visualizer and replay aid for troubleshooting, investigation, and homelab visibility.',
  },
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

function isGatewayCandidate(ip) {
  const parts = parseIpv4(ip)
  return Boolean(parts && isPrivateIpv4(ip) && parts[3] === 1)
}

function isSpecialIpv4(ip) {
  const parts = parseIpv4(ip)
  if (!parts) return true

  const [a, b, , d] = parts
  return (
    a === 0 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a >= 224 && a <= 239) ||
    ip === '255.255.255.255' ||
    d === 255
  )
}

function isLanUnicast(ip) {
  return isPrivateIpv4(ip) && !isSpecialIpv4(ip)
}

function makeTextSprite(text, accent = '#d8d8dc') {
  const canvas = document.createElement('canvas')
  canvas.width = 768
  canvas.height = 192

  const ctx = canvas.getContext('2d')
  ctx.clearRect(0, 0, canvas.width, canvas.height)
  ctx.font = '800 50px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillStyle = 'rgba(6, 6, 7, 0.94)'
  ctx.fillRect(24, 42, 720, 108)
  ctx.strokeStyle = accent
  ctx.lineWidth = 4
  ctx.strokeRect(24, 42, 720, 108)
  ctx.fillStyle = '#f7fbfa'
  ctx.fillText(text, 384, 96)

  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: false })
  const sprite = new THREE.Sprite(material)
  sprite.scale.set(112, 28, 1)
  return sprite
}

function updateTextSprite(sprite, text, accent = '#d8d8dc') {
  const nextSprite = makeTextSprite(text, accent)
  const previousMap = sprite.material.map
  sprite.material.map = nextSprite.material.map
  sprite.material.needsUpdate = true
  previousMap?.dispose()
  nextSprite.material.dispose()
}

function setCylinderBetween(mesh, start, end, radius) {
  const direction = new THREE.Vector3().subVectors(end, start)
  const length = Math.max(direction.length(), 0.1)
  const midpoint = new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5)

  mesh.position.copy(midpoint)
  mesh.scale.set(radius, length, radius)
  mesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction.normalize())
}

function randomPosition(index) {
  const angle = index * 2.399963
  const radius = 95 + (index % 5) * 19
  return {
    x: Math.cos(angle) * radius,
    y: ((index % 7) - 3) * 20,
    z: Math.sin(angle) * radius,
  }
}

function nodeMass(node) {
  return THREE.MathUtils.clamp(1 + Math.log10(node.bytes + 1) * 0.7 + Math.sqrt(node.packets) * 0.025, 1, 9)
}

function nodeRadius(node) {
  return THREE.MathUtils.clamp(8 + nodeMass(node) * 2.1, 10, 27)
}

function nodeRenderScale(node) {
  return node.renderScale || 1
}

function renderedNodeRadius(node) {
  return nodeRadius(node) * nodeRenderScale(node)
}

function pulseRadius(node) {
  return THREE.MathUtils.clamp(node.recentBytes / 4500, 0, 1.8) * 8
}

function collisionNodeRadius(node) {
  return renderedNodeRadius(node) + pulseRadius(node)
}

function ringCapacityScale(nodes, radius) {
  if (nodes.length <= 1 || radius <= 0) return 1

  const requiredArc = nodes.reduce(
    (total, node) => total + nodeRadius(node) * 2 + NODE_RING_GAP,
    0,
  )
  const availableArc = Math.PI * 2 * radius

  return THREE.MathUtils.clamp(availableArc / Math.max(requiredArc, 1), MIN_NODE_SCALE, 1)
}

function requiredRingRadius(nodes) {
  if (nodes.length <= 1) return 0

  const requiredArc = nodes.reduce(
    (total, node) => total + nodeRadius(node) * 2 + NODE_RING_GAP,
    0,
  )

  return (requiredArc * NETWORK_RING_PADDING) / (Math.PI * 2)
}

function flatRingPosition(index, count, radius, yOffset = 0) {
  if (radius === 0) return new THREE.Vector3(0, yOffset, 0)

  const angle = (index / Math.max(count, 1)) * Math.PI * 2 - Math.PI / 2

  return new THREE.Vector3(
    Math.cos(angle) * radius,
    yOffset,
    Math.sin(angle) * radius,
  )
}

function makeRingGuide(radius, yOffset) {
  const points = []
  const segments = 160

  for (let index = 0; index <= segments; index += 1) {
    const angle = (index / segments) * Math.PI * 2
    points.push(new THREE.Vector3(Math.cos(angle) * radius, yOffset, Math.sin(angle) * radius))
  }

  const geometry = new THREE.BufferGeometry().setFromPoints(points)
  const material = new THREE.LineBasicMaterial({
    color: 0xf4f4f5,
    transparent: true,
    opacity: 0.12,
  })

  const guide = new THREE.Line(geometry, material)
  guide.userData.radius = radius
  guide.userData.yOffset = yOffset
  return guide
}

function updateRingGuide(guide, radius, yOffset) {
  if (guide.userData.radius === radius && guide.userData.yOffset === yOffset) return

  const points = []
  const segments = 160

  for (let index = 0; index <= segments; index += 1) {
    const angle = (index / segments) * Math.PI * 2
    points.push(new THREE.Vector3(Math.cos(angle) * radius, yOffset, Math.sin(angle) * radius))
  }

  guide.geometry.dispose()
  guide.geometry = new THREE.BufferGeometry().setFromPoints(points)
  guide.userData.radius = radius
  guide.userData.yOffset = yOffset
}

export default function App() {
  const mountRef = useRef(null)
  const nodesRef = useRef(new Map())
  const edgesRef = useRef(new Map())
  const packetsRef = useRef([])
  const frameRef = useRef(0)
  const websocketRef = useRef(null)
  const selectedIpRef = useRef(null)
  const appModeRef = useRef('live')
  const showLabelsRef = useRef(true)
  const labelModeRef = useRef('resolvedIp')
  const hostnamesRef = useRef(new Map())
  const macNamesRef = useRef(new Map())
  const cameraRef = useRef(null)
  const ingestPacketRef = useRef(null)
  const resetGraphRef = useRef(null)
  const snapshotGraphRef = useRef(null)

  const [activeTab, setActiveTab] = useState('live')
  const [appMode, setAppMode] = useState('live')
  const [cameraZoom, setCameraZoom] = useState(DEFAULT_CAMERA_ZOOM)
  const [showLabels, setShowLabels] = useState(true)
  const [labelMode, setLabelMode] = useState('resolvedIp')
  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [status, setStatus] = useState('connecting')
  const [captureMessage, setCaptureMessage] = useState('')
  const [captureInterface, setCaptureInterface] = useState('en0')
  const [copiedCommand, setCopiedCommand] = useState(false)
  const [selectedIp, setSelectedIp] = useState(null)
  const [isDeviceDrawerOpen, setIsDeviceDrawerOpen] = useState(false)
  const [isStatsDrawerOpen, setIsStatsDrawerOpen] = useState(false)
  const [isConversationRankOpen, setIsConversationRankOpen] = useState(true)
  const [isWorkflowPanelOpen, setIsWorkflowPanelOpen] = useState(true)
  const [conversationSort, setConversationSort] = useState('bytes')
  const [replayPackets, setReplayPackets] = useState([])
  const [replayMeta, setReplayMeta] = useState(null)
  const [replayState, setReplayState] = useState('idle')
  const [replayIndex, setReplayIndex] = useState(0)
  const [replayTime, setReplayTime] = useState(0)
  const [replaySpeed, setReplaySpeed] = useState(1)
  const [replayError, setReplayError] = useState('')

  const liveCommand = useMemo(() => {
    const iface = captureInterface.trim()
    return `npm start${iface ? ` -- --iface ${iface}` : ''}`
  }, [captureInterface])

  const selectedNode = useMemo(
    () => nodes.find((node) => node.ip === selectedIp),
    [nodes, selectedIp],
  )

  const selectedNeighborhood = useMemo(() => {
    if (!selectedIp) return { oneHop: [] }

    const adjacency = new Map()
    edges.forEach((edge) => {
      if (!adjacency.has(edge.src)) adjacency.set(edge.src, new Set())
      if (!adjacency.has(edge.dst)) adjacency.set(edge.dst, new Set())
      adjacency.get(edge.src).add(edge.dst)
      adjacency.get(edge.dst).add(edge.src)
    })

    return { oneHop: [...(adjacency.get(selectedIp) || [])].sort() }
  }, [edges, selectedIp])

  const visibleEdges = useMemo(() => {
    if (!selectedIp) return edges
    return edges.filter((edge) => edge.src === selectedIp || edge.dst === selectedIp)
  }, [edges, selectedIp])

  const networkStats = useMemo(() => {
    const totalBytes = nodes.reduce((total, node) => total + node.bytes, 0)
    const totalPackets = nodes.reduce((total, node) => total + node.packets, 0)
    return {
      totalBytes,
      totalPackets,
      hosts: nodes.length,
      links: edges.length,
    }
  }, [edges.length, nodes])

  const topConversations = useMemo(
    () => edges.slice(0, 8),
    [edges],
  )

  const replayAnalysis = useMemo(() => {
    const conversations = new Map()
    const endpoints = new Map()
    const protocols = new Map()
    const hostnames = new Map()
    const macNames = new Map()
    const timelineBuckets = Array.from({ length: 40 }, () => 0)
    const duration = Math.max(replayMeta?.duration || 0, 0.1)

    replayPackets.forEach((packet) => {
      const size = Number(packet.size) || 0
      const proto = packet.proto || 'OTHER'
      const src = packet.src || packet.srcIp
      const dst = packet.dst || packet.dstIp
      if (!src || !dst) return

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
        first: packet.replayTime,
        last: packet.replayTime,
      }
      conversation.bytes += size
      conversation.packets += 1
      conversation.first = Math.min(conversation.first, packet.replayTime)
      conversation.last = Math.max(conversation.last, packet.replayTime)
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

      const bucket = Math.min(timelineBuckets.length - 1, Math.floor((packet.replayTime / duration) * timelineBuckets.length))
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
    }
  }, [conversationSort, replayMeta, replayPackets])

  useEffect(() => {
    selectedIpRef.current = selectedIp
  }, [selectedIp])

  useEffect(() => {
    appModeRef.current = appMode
  }, [appMode])

  useEffect(() => {
    showLabelsRef.current = showLabels
  }, [showLabels])

  useEffect(() => {
    labelModeRef.current = labelMode
    setShowLabels(labelMode !== 'off')
  }, [labelMode])

  useEffect(() => {
    hostnamesRef.current = replayAnalysis.hostnames
    macNamesRef.current = replayAnalysis.macNames
  }, [replayAnalysis.hostnames, replayAnalysis.macNames])

  useEffect(() => {
    if (!cameraRef.current) return
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

    const viewSize = 760
    const aspect = mount.clientWidth / mount.clientHeight
    const camera = new THREE.OrthographicCamera(
      (-viewSize * aspect) / 2,
      (viewSize * aspect) / 2,
      viewSize / 2,
      -viewSize / 2,
      0.1,
      2200,
    )
    camera.position.set(0, 900, 0)
    camera.lookAt(0, 0, 0)
    camera.up.set(0, 0, -1)
    camera.zoom = DEFAULT_CAMERA_ZOOM
    camera.updateProjectionMatrix()
    cameraRef.current = camera

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

    const nodeGeometry = new THREE.SphereGeometry(8, 32, 24)
    const edgeGeometry = new THREE.CylinderGeometry(1, 1, 1, 10)
    const packetGeometry = new THREE.SphereGeometry(2.5, 12, 12)
    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2()
    const ringGuides = NETWORK_RING_RADII.slice(1).map((radius, index) => {
      const guide = makeRingGuide(radius, (index + 1) * -8)
      scene.add(guide)
      return guide
    })
    const ringLabels = NETWORK_RING_RADII.map((radius, index) => {
      const label = makeTextSprite(`HOP ${index}`)
      label.position.set(0, index * -8 + 20, radius === 0 ? -44 : -radius)
      label.scale.set(44, 11, 1)
      scene.add(label)
      return label
    })

    function setRingOverlay(hasFocus, ringRadii = NETWORK_RING_RADII) {
      const labelsEnabled = showLabelsRef.current

      ringGuides.forEach((guide, index) => {
        const ringIndex = index + 1
        const visible = hasFocus ? ringIndex === 1 : true
        guide.visible = visible
        if (visible) updateRingGuide(guide, ringRadii[ringIndex], ringIndex * -8)
      })

      ringLabels.forEach((label, ringIndex) => {
        const visible = hasFocus ? ringIndex <= 1 : true
        const radius = ringRadii[ringIndex] || 0
        label.visible = visible && labelsEnabled
        label.position.set(0, ringIndex * -8 + 20, radius === 0 ? -44 : -radius)
      })
    }

    function snapshotState() {
      const connectedIps = new Set()
      edgeStore.forEach((edge) => {
        connectedIps.add(edge.src)
        connectedIps.add(edge.dst)
      })

      const nextNodes = [...nodeStore.values()]
        .filter((node) => connectedIps.has(node.ip))
        .map((node) => ({
          ip: node.ip,
          bytes: node.bytes,
          packets: node.packets,
          rate: node.recentBytes,
        }))
        .sort((a, b) => b.bytes - a.bytes)

      const nextEdges = [...edgeStore.values()]
        .map((edge) => ({
          key: edge.key,
          src: edge.src,
          dst: edge.dst,
          bytes: edge.bytes,
          packets: edge.packets,
        }))
        .sort((a, b) => b.bytes - a.bytes)

      setNodes(nextNodes)
      setEdges(nextEdges)
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
      setNodes([])
      setEdges([])
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
        ring: null,
        mac: '',
        labelText: ip,
      }

      nodeStore.set(ip, node)
      snapshotState()
      return node
    }

    function ensureEdge(src, dst) {
      const key = edgeKey(src, dst)
      if (edgeStore.has(key)) return edgeStore.get(key)

      const material = new THREE.MeshBasicMaterial({
        color: 0xb7b7bd,
        transparent: true,
        opacity: 0.46,
      })
      const mesh = new THREE.Mesh(edgeGeometry, material)
      scene.add(mesh)

      const edge = { key, src, dst, mesh, bytes: 0, packets: 0, recentBytes: 0 }
      edgeStore.set(key, edge)
      snapshotState()
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

    function assignRadialFocusTargets(selected, depths) {
      const depthOne = []

      depths.forEach((depth, ip) => {
        if (depth === 1) depthOne.push(ip)
      })

      depthOne.sort()

      const selectedNode = nodeStore.get(selected)
      const depthOneNodes = depthOne.map((ip) => nodeStore.get(ip)).filter(Boolean)
      const centerClearance = selectedNode
        ? nodeRadius(selectedNode) + Math.max(...depthOneNodes.map((node) => nodeRadius(node)), 0) + NODE_RING_GAP
        : FOCUS_RING_RADIUS
      const focusRadius = Math.min(
        Math.max(FOCUS_RING_RADIUS, requiredRingRadius(depthOneNodes), centerClearance),
        FOCUS_RING_MAX_RADIUS,
      )
      const focusScale = ringCapacityScale(depthOneNodes, focusRadius)
      if (selectedNode) {
        selectedNode.tx = 0
        selectedNode.ty = 0
        selectedNode.tz = 0
        selectedNode.renderScale = focusScale
        selectedNode.ring = 0
      }

      setRingOverlay(true, [0, focusRadius, 0, 0])

      depthOne.forEach((ip, index) => {
        const node = nodeStore.get(ip)
        const target = flatRingPosition(index, depthOne.length, focusRadius, -8)
        node.tx = target.x
        node.ty = target.y
        node.tz = target.z
        node.renderScale = focusScale
        node.ring = 1
      })
    }

    function assignNetworkRingTargets(nodeList, edgeList, adjacency) {
      const visibleNodes = nodeList.filter((node) => (adjacency.get(node.ip)?.size || 0) > 0)
      const realLanNodes = visibleNodes.filter((node) => isLanUnicast(node.ip))
      const gateway =
        realLanNodes
          .filter((node) => isGatewayCandidate(node.ip))
          .sort((a, b) => b.bytes - a.bytes || b.packets - a.packets)[0] ||
        realLanNodes.sort((a, b) => b.bytes - a.bytes || b.packets - a.packets)[0] ||
        visibleNodes.sort((a, b) => b.bytes - a.bytes || b.packets - a.packets)[0]

      const gatewayIp = gateway?.ip
      const gatewayNeighbors = gatewayIp ? adjacency.get(gatewayIp) || new Set() : new Set()
      const realPeerTraffic = realLanNodes
        .filter((node) => node.ip !== gatewayIp)
        .map((node) => node.bytes + node.recentBytes * 4 + node.packets * 64)
        .sort((a, b) => a - b)
      const activityCutoff = realPeerTraffic.length
        ? realPeerTraffic[Math.floor(realPeerTraffic.length * 0.55)]
        : 0
      const linkedToGatewayBytes = new Map()

      edgeList.forEach((edge) => {
        if (edge.src === gatewayIp) linkedToGatewayBytes.set(edge.dst, edge.bytes)
        if (edge.dst === gatewayIp) linkedToGatewayBytes.set(edge.src, edge.bytes)
      })

      const rings = [[], [], [], []]

      visibleNodes.forEach((node) => {
        if (node.ip === gatewayIp) {
          rings[0].push(node)
          return
        }

        if (isSpecialIpv4(node.ip)) {
          rings[3].push(node)
          return
        }

        const trafficScore = node.bytes + node.recentBytes * 4 + node.packets * 64
        const gatewayEdgeBytes = linkedToGatewayBytes.get(node.ip) || 0
        const isDirectActivePeer =
          isLanUnicast(node.ip) &&
          gatewayNeighbors.has(node.ip) &&
          (trafficScore >= activityCutoff || gatewayEdgeBytes >= 2048 || node.packets >= 4)

        if (isDirectActivePeer) {
          rings[1].push(node)
          return
        }

        rings[2].push(node)
      })

      rings.forEach((ring) => {
        ring.sort((a, b) => b.bytes - a.bytes || a.ip.localeCompare(b.ip))
      })

      const ringRadii = [0]
      for (let ringIndex = 1; ringIndex < rings.length; ringIndex += 1) {
        const previousRadius = ringRadii[ringIndex - 1]
        const roomyRadius = Math.max(NETWORK_RING_RADII[ringIndex], requiredRingRadius(rings[ringIndex]))
        const separatedRadius = Math.max(roomyRadius, previousRadius + NETWORK_RING_SEPARATION)
        const maxRadius = Math.max(NETWORK_RING_MAX_RADII[ringIndex], previousRadius + NETWORK_RING_SEPARATION)
        ringRadii[ringIndex] = Math.min(separatedRadius, maxRadius)
      }
      const ringScales = rings.map((ring, ringIndex) =>
        ringCapacityScale(ring, ringRadii[ringIndex]),
      )

      rings.forEach((ring, ringIndex) => {
        const radius = ringRadii[ringIndex]

        ring.forEach((node, index) => {
          const target = flatRingPosition(index, ring.length, radius, ringIndex * -8)
          node.tx = target.x
          node.ty = target.y
          node.tz = target.z
          node.ring = ringIndex
          node.renderScale = ringScales[ringIndex]
        })
      })

      setRingOverlay(false, ringRadii)

      return { gatewayIp, rings, ringRadii }
    }

    function applyGraphForces() {
      const nodeList = [...nodeStore.values()]
      const edgeList = [...edgeStore.values()]
      const selected = selectedIpRef.current
      const depths = focusDepths(selected)
      const hasFocus = depths.size > 0
      const adjacency = buildAdjacency()

      if (hasFocus) assignRadialFocusTargets(selected, depths)
      if (!hasFocus) assignNetworkRingTargets(nodeList, edgeList, adjacency)

      nodeList.forEach((node) => {
        const isConnected = (adjacency.get(node.ip)?.size || 0) > 0
        const depth = hasFocus ? depths.get(node.ip) : undefined
        node.group.visible = hasFocus ? depth !== undefined : isConnected

        const hiddenPull = hasFocus && depth === undefined ? 0.018 : hasFocus ? 0.045 : 0.07
        const dx = node.tx - node.x
        const dy = node.ty - node.y
        const dz = node.tz - node.z
        node.vx += dx * hiddenPull
        node.vy += dy * hiddenPull
        node.vz += dz * hiddenPull

        if (hasFocus && depth === undefined) {
          node.renderScale = MIN_NODE_SCALE
          node.vx += (node.x > 0 ? 1 : -1) * 0.03
          node.vy -= 0.015
          node.vz += (node.z > 0 ? 1 : -1) * 0.03
        }
      })

      for (let i = 0; i < nodeList.length; i += 1) {
        for (let j = i + 1; j < nodeList.length; j += 1) {
          const a = nodeList[i]
          const b = nodeList[j]
          const depthA = hasFocus ? depths.get(a.ip) : 0
          const depthB = hasFocus ? depths.get(b.ip) : 0
          if (hasFocus && depthA === undefined && depthB === undefined) continue

          const dx = b.x - a.x
          const dy = b.y - a.y
          const dz = b.z - a.z
          const distanceSq = Math.max(dx * dx + dy * dy + dz * dz, 0.01)
          const distance = Math.sqrt(distanceSq)
          const sameNetworkRing = !hasFocus && a.ring === b.ring
          const spacing = collisionNodeRadius(a) + collisionNodeRadius(b) + (hasFocus ? 26 : sameNetworkRing ? 34 : 18)
          const repel = Math.min((spacing * spacing) / distanceSq, 2.2) * (hasFocus ? 0.05 : 0.035)
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
        edge.mesh.visible = !hasFocus || (depths.has(edge.src) && depths.has(edge.dst))

        if (!hasFocus) return

        const dx = b.x - a.x
        const dy = b.y - a.y
        const dz = b.z - a.z
        const distance = Math.max(Math.sqrt(dx * dx + dy * dy + dz * dz), 0.01)
        const strength = THREE.MathUtils.clamp(Math.log10(edge.bytes + 1) * 0.0035 + 0.006, 0.006, 0.026)
        const desired = 105
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

      nodeList.forEach((node) => {
        node.vx *= 0.82
        node.vy *= 0.82
        node.vz *= 0.82
        node.x += THREE.MathUtils.clamp(node.vx, -4.6, 4.6)
        node.y += THREE.MathUtils.clamp(node.vy, -4.6, 4.6)
        node.z += THREE.MathUtils.clamp(node.vz, -4.6, 4.6)
      })

      for (let i = 0; i < nodeList.length; i += 1) {
        for (let j = i + 1; j < nodeList.length; j += 1) {
          const a = nodeList[i]
          const b = nodeList[j]
          if (!a.group.visible || !b.group.visible) continue

          const sameNetworkRing = !hasFocus && a.ring === b.ring
          const minDistance = collisionNodeRadius(a) + collisionNodeRadius(b) + (sameNetworkRing ? 10 : 6)
          const dx = b.x - a.x
          const dy = b.y - a.y
          const dz = b.z - a.z
          const distance = Math.max(Math.sqrt(dx * dx + dy * dy + dz * dz), 0.01)
          if (distance >= minDistance) continue

          const push = (minDistance - distance) * 0.5
          const nx = dx / distance
          const ny = dy / distance
          const nz = dz / distance

          if (a.ring !== 0 || hasFocus) {
            a.x -= nx * push
            a.y -= ny * push
            a.z -= nz * push
          }
          if (b.ring !== 0 || hasFocus) {
            b.x += nx * push
            b.y += ny * push
            b.z += nz * push
          }
        }
      }

      nodeList.forEach((node) => {
        if (!node.group.visible) return
        node.x = node.tx
        node.y = THREE.MathUtils.lerp(node.y, node.ty, 0.35)
        node.z = node.tz
        node.vx = 0
        node.vz = 0
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
      const scale = THREE.MathUtils.clamp(0.8 + size / 900, 0.8, 2.4)
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
          ? { 0: 1, 1: 0.94 }[depth] || 0
          : 1
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
          !labelsEnabled || (hasFocus && depth === undefined) ? 0 : Math.max(visibleWeight, 0.88),
          0.14,
        )
        node.label.position.y = 22 + scale * 7
        node.label.scale.lerp(new THREE.Vector3(112 * labelScale, 28 * labelScale, 1), 0.18)
        node.recentBytes *= 0.91
      })

      edgeList.forEach((edge) => {
        const a = nodeStore.get(edge.src)
        const b = nodeStore.get(edge.dst)
        if (!a || !b) return

        const start = new THREE.Vector3(a.x, a.y, a.z)
        const end = new THREE.Vector3(b.x, b.y, b.z)
        const radius = THREE.MathUtils.clamp(0.36 + Math.log10(edge.bytes + 1) * 0.13, 0.36, 2.35)
        const srcDepth = hasFocus ? depths.get(edge.src) : 0
        const dstDepth = hasFocus ? depths.get(edge.dst) : 0
        const focusedEdge = !hasFocus || (srcDepth !== undefined && dstDepth !== undefined)
        const baseOpacity = focusedEdge ? 0.28 : 0
        const maxOpacity = focusedEdge ? 0.78 : 0
        edge.mesh.material.opacity = THREE.MathUtils.clamp(baseOpacity + edge.recentBytes / 5500, baseOpacity, maxOpacity)
        setCylinderBetween(edge.mesh, start, end, radius)
        edge.recentBytes *= 0.88
      })
    }

    function updatePackets() {
      const remove = []
      const selected = selectedIpRef.current
      const depths = selected ? focusDepths(selected) : null

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

    function animate() {
      frameRef.current = requestAnimationFrame(animate)
      updateGraphVisuals()
      updatePackets()

      nodeStore.forEach((node) => {
        node.label.quaternion.copy(camera.quaternion)
      })
      ringLabels.forEach((label) => {
        label.quaternion.copy(camera.quaternion)
      })

      if (Math.random() < 0.03) snapshotState()
      renderer.render(scene, camera)
    }

    function handlePointerDown(event) {
      const bounds = renderer.domElement.getBoundingClientRect()
      pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1
      pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1
      raycaster.setFromCamera(pointer, camera)
      const meshes = [...nodeStore.values()].filter((node) => node.group.visible).map((node) => node.mesh)
      const hit = raycaster.intersectObjects(meshes, false)[0]
      if (hit?.object?.userData?.ip) {
        setSelectedIp(hit.object.userData.ip)
      } else if (selectedIpRef.current) {
        setSelectedIp(null)
      }
    }

    function handleWheel(event) {
      event.preventDefault()
      const direction = event.deltaY > 0 ? -0.12 : 0.12
      setCameraZoom((zoom) => clampZoom(zoom + direction))
    }

    function handleResize() {
      const nextAspect = mount.clientWidth / mount.clientHeight
      camera.left = (-viewSize * nextAspect) / 2
      camera.right = (viewSize * nextAspect) / 2
      camera.top = viewSize / 2
      camera.bottom = -viewSize / 2
      camera.updateProjectionMatrix()
      renderer.setSize(mount.clientWidth, mount.clientHeight)
    }

    renderer.domElement.addEventListener('pointerdown', handlePointerDown)
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
      if (data.type === 'packet' && appModeRef.current === 'live') ingestPacket(data)
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

    const summaryTimer = window.setInterval(snapshotState, 900)

    return () => {
      window.clearInterval(summaryTimer)
      ws.close()
      cancelAnimationFrame(frameRef.current)
      window.removeEventListener('resize', handleResize)
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
        edge.mesh.material.dispose()
      })
      packetStore.forEach((packet) => {
        scene.remove(packet.mesh)
        packet.mesh.material.dispose()
      })
      nodeGeometry.dispose()
      edgeGeometry.dispose()
      packetGeometry.dispose()
      ringGuides.forEach((guide) => {
        scene.remove(guide)
        guide.geometry.dispose()
        guide.material.dispose()
      })
      ringLabels.forEach((label) => {
        scene.remove(label)
        label.material.map.dispose()
        label.material.dispose()
      })
      ingestPacketRef.current = null
      resetGraphRef.current = null
      snapshotGraphRef.current = null
      cameraRef.current = null
      renderer.dispose()

      if (mount.contains(renderer.domElement)) {
        mount.removeChild(renderer.domElement)
      }
    }
  }, [])

  function requestCapture() {
    setActiveTab('live')
    setAppMode('live')
    setReplayState('idle')
    resetGraphRef.current?.()

    if (websocketRef.current?.readyState !== WebSocket.OPEN) {
      setStatus('offline')
      return
    }

    setStatus('starting')
    websocketRef.current.send(JSON.stringify({ type: 'start_capture' }))
  }

  async function copyLiveCommand() {
    try {
      await navigator.clipboard.writeText(liveCommand)
      setCopiedCommand(true)
      window.setTimeout(() => setCopiedCommand(false), 1400)
    } catch {
      setCopiedCommand(false)
    }
  }

  async function handleReplayFile(event) {
    const file = event.target.files?.[0]
    if (!file) return

    setActiveTab('replay')
    setAppMode('replay')
    setReplayError('')
    setReplayState('idle')
    setReplayIndex(0)
    setReplayTime(0)
    resetGraphRef.current?.()

    try {
      const parsed = parseCaptureBuffer(await file.arrayBuffer())
      setReplayPackets(parsed.packets)
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
      ingestPacketRef.current?.(replayPackets[nextIndex])
      nextIndex += 1
    }
    snapshotGraphRef.current?.()
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
            ingestPacketRef.current?.(replayPackets[nextIndex])
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
  const activeTabContent = {
    live: (
      <section className="tabContent liveWorkspacePanel" aria-label="Live capture setup">
        <div className="modeHeading">
          <p>Live Capture</p>
          <h2>{status === 'live' ? 'Live traffic is streaming.' : 'Inspect traffic as it happens.'}</h2>
        </div>
        {status === 'live' && (
          <dl className="liveStatus">
            <div>
              <dt>Hosts</dt>
              <dd>{networkStats.hosts.toLocaleString()}</dd>
            </div>
            <div>
              <dt>Links</dt>
              <dd>{networkStats.links.toLocaleString()}</dd>
            </div>
            <div>
              <dt>Data</dt>
              <dd>{byteLabel(networkStats.totalBytes)}</dd>
            </div>
          </dl>
        )}
        <ol className="steps">
          <li>Choose the interface that should be captured.</li>
          <li>Run the terminal command so the local helper can access packets.</li>
          <li>Start capture here after the WebSocket server connects.</li>
        </ol>
        <label className="fieldLabel" htmlFor="capture-interface">
          Interface
        </label>
        <input
          id="capture-interface"
          value={captureInterface}
          onChange={(event) => setCaptureInterface(event.target.value)}
          placeholder="en0, eth0, wlan0"
        />
        <div className="exampleChips" aria-label="Interface examples">
          {['en0', 'eth0', 'wlan0'].map((iface) => (
            <button type="button" key={iface} onClick={() => setCaptureInterface(iface)}>
              {iface}
            </button>
          ))}
        </div>
        <div className="commandBlock">
          <code>{liveCommand}</code>
          <button type="button" onClick={copyLiveCommand}>
            {copiedCommand ? 'Copied' : 'Copy'}
          </button>
        </div>
        <p className="noteText">
          Browsers cannot capture raw packets. PacMap uses the local Python helper launched by this
          command. Use an Administrator terminal on Windows; macOS and Linux may need sudo or
          another elevated shell.
        </p>
        {captureMessage && <p className="permissionError">{captureMessage}</p>}
        <button className="primaryAction" type="button" onClick={requestCapture}>
          {needsCapturePermission ? 'Start live capture' : 'Restart live view'}
        </button>
      </section>
    ),
    replay: (
      <section className="tabContent replayWorkspacePanel" aria-label="PCAP replay setup">
        <div className="modeHeading">
          <p>Replay PCAP</p>
          <h2>Inspect a saved capture over time.</h2>
        </div>
        <label className="uploadZone">
          <input type="file" accept=".pcap,.pcapng" onChange={handleReplayFile} />
          <strong>Upload .pcap or .pcapng</strong>
          <span>Common IPv4 and IPv6 TCP, UDP, and DNS captures are replayed on the map.</span>
        </label>
        {replayError && <p className="permissionError">{replayError}</p>}
        {replayMeta && (
          <>
            <dl className="replayStats">
              <div>
                <dt>File</dt>
                <dd>{replayMeta.name}</dd>
              </div>
              <div>
                <dt>Parsed</dt>
                <dd>{replayMeta.parsed.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Skipped</dt>
                <dd>{replayMeta.skipped.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Time</dt>
                <dd>{replayTime.toFixed(1)}s</dd>
              </div>
              <div>
                <dt>Detected</dt>
                <dd>
                  {replayMeta.linkTypes?.length
                    ? replayMeta.linkTypes.map(linkTypeLabel).join(', ')
                    : 'Unknown'}
                </dd>
              </div>
            </dl>
            <div className="playbackControls" aria-label="Replay controls">
              <button
                className="playButton"
                type="button"
                disabled={!replayPackets.length}
                onClick={() => setReplayState(replayState === 'playing' ? 'paused' : 'playing')}
              >
                {replayState === 'playing' ? 'Pause' : 'Play'}
              </button>
              <button type="button" disabled={!replayPackets.length} onClick={() => restartReplay('paused')}>
                Restart
              </button>
              <select
                value={replaySpeed}
                onChange={(event) => setReplaySpeed(Number(event.target.value))}
                aria-label="Replay speed"
              >
                {[0.25, 0.5, 1, 2, 4].map((speed) => (
                  <option key={speed} value={speed}>
                    {speed}x
                  </option>
                ))}
              </select>
            </div>
            <input
              className="timeline"
              type="range"
              min="0"
              max={Math.max(replayMeta.duration, 0.1)}
              step="0.1"
              value={Math.min(replayTime, Math.max(replayMeta.duration, 0.1))}
              onChange={(event) => scrubReplay(event.target.value)}
              aria-label="Replay timeline"
            />
            <p className="noteText">
              {replayIndex.toLocaleString()} of {replayPackets.length.toLocaleString()} packets replayed.
            </p>
            <div className="analysisPanel" aria-label="Wireshark-inspired analysis">
              <section>
                <h3>Name resolution</h3>
                <div className="labelModeGrid">
                  {Object.entries(LABEL_MODES).map(([mode, label]) => (
                    <button
                      className={labelMode === mode ? 'active' : ''}
                      key={mode}
                      type="button"
                      onClick={() => setLabelMode(mode)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </section>

              <section>
                <h3>Protocol breakdown</h3>
                <div className="miniRows">
                  {replayAnalysis.protocols.slice(0, 5).map((protocol) => (
                    <span key={protocol.proto}>
                      <i style={{ background: PROTOCOLS[protocol.proto]?.css || PROTOCOLS.OTHER.css }} />
                      {protocol.proto} {byteLabel(protocol.bytes)}
                    </span>
                  ))}
                  {replayAnalysis.protocols.length === 0 && <p className="emptyText">No packets parsed yet.</p>}
                </div>
              </section>

              <section>
                <h3>Endpoints</h3>
                <div className="miniRows">
                  {replayAnalysis.endpoints.slice(0, 5).map((endpoint) => (
                    <button type="button" key={endpoint.ip} onClick={() => setSelectedIp(endpoint.ip)}>
                      {endpoint.ip} {byteLabel(endpoint.bytes)}
                    </button>
                  ))}
                </div>
              </section>

              <section>
                <h3>I/O timeline</h3>
                <div className="ioTimeline" aria-label="Replay traffic timeline">
                  {replayAnalysis.timelineBuckets.map((bytes, index) => (
                    <i
                      key={`${index}-${bytes}`}
                      style={{ height: `${Math.max(4, (bytes / replayAnalysis.maxBucket) * 44)}px` }}
                    />
                  ))}
                </div>
              </section>
            </div>
          </>
        )}
      </section>
    ),
    instructions: (
      <section className="tabContent" aria-label="Instructions">
        <div className="modeHeading">
          <p>Instructions</p>
          <h2>Two ways to investigate packet flow.</h2>
        </div>
        <div className="instructionList">
          <p>
            <strong>Live Capture</strong> maps traffic from your machine or network right now. It
            requires local packet access through the Python helper.
          </p>
          <p>
            <strong>Replay PCAP</strong> maps a saved capture without starting the Python server.
            Upload a file and use playback controls to inspect activity over time.
          </p>
          <p>
            Install once with <code>pip install websockets scapy</code> and{' '}
            <code>npm install --prefix client</code>. Start with <code>{liveCommand}</code>.
          </p>
        </div>
        <div className="protocolLegend" aria-label="Protocol colors">
          {Object.entries(PROTOCOLS).map(([key, protocol]) => (
            <span key={key}>
              <i style={{ background: protocol.css }} />
              {protocol.label}
            </span>
          ))}
        </div>
      </section>
    ),
  }

  return (
    <main className="appShell">
      <HeroAsciiOne>
        <nav className="appTabs" aria-label="PacMap tabs">
          {Object.entries(TABS).map(([tab, label]) => (
            <button
              className={activeTab === tab ? 'appTab active' : 'appTab'}
              key={tab}
              type="button"
              onClick={() => {
                setActiveTab(tab)
                if (tab === 'live' || tab === 'replay') {
                  setAppMode(tab)
                  resetGraphRef.current?.()
                  setReplayState(tab === 'replay' && replayPackets.length ? 'paused' : 'idle')
                  setReplayIndex(0)
                  setReplayTime(0)
                }
              }}
            >
              {label}
            </button>
          ))}
        </nav>

        <section
          className={activeTab !== 'instructions' ? 'viewport' : 'viewport tabHidden'}
          aria-label={`${TABS[activeTab]} packet map`}
        >
        <div ref={mountRef} className="canvasMount" />

        {isWorkflowPanelOpen && activeTab === 'live' && activeTabContent.live}
        {isWorkflowPanelOpen && activeTab === 'replay' && activeTabContent.replay}

        <header className="topBar" aria-label="App status">
          <div className="brandBlock">
            <p>pacmap</p>
          </div>
        </header>

        <section className="graphToolbar" aria-label="Graph controls">
          {activeTab !== 'instructions' && (
            <button type="button" onClick={() => setIsWorkflowPanelOpen((open) => !open)}>
              {isWorkflowPanelOpen ? 'Hide panel' : 'Panel'}
            </button>
          )}
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
          <button type="button" onClick={() => setIsStatsDrawerOpen((open) => !open)}>
            {isStatsDrawerOpen ? 'Hide stats' : 'Stats'}
          </button>
          <span>{Math.round(cameraZoom * 100)}%</span>
        </section>

        <button
          className="drawerToggle"
          type="button"
          aria-expanded={isDeviceDrawerOpen}
          onClick={() => setIsDeviceDrawerOpen((open) => !open)}
        >
          Devices <strong>{nodes.length}</strong>
        </button>

        {selectedIp && (
          <button className="wholeNetworkButton" type="button" onClick={() => setSelectedIp(null)}>
            Whole network
          </button>
        )}

        <aside
          className={isDeviceDrawerOpen ? 'deviceDrawer open' : 'deviceDrawer'}
          aria-label="Largest connected devices"
        >
          <section className="panel">
            <div className="panelTitle">
              <h2>Largest devices</h2>
              <button type="button" onClick={() => setIsDeviceDrawerOpen(false)}>
                Close
              </button>
            </div>
            <div className="nodeList">
              {nodes.slice(0, NODE_LIMIT).map((node) => (
                <button
                  className={node.ip === selectedIp ? 'nodeRow selected' : 'nodeRow'}
                  key={node.ip}
                  type="button"
                  onClick={() => setSelectedIp(node.ip)}
                >
                  <span>{node.ip}</span>
                  <strong>{byteLabel(node.bytes)}</strong>
                </button>
              ))}
              {nodes.length === 0 && (
                <p className="emptyText">Start capture, then use the network normally.</p>
              )}
            </div>
          </section>

          {selectedNode && (
            <section className="panel selectedPanel">
              <div className="panelTitle">
                <h2>{selectedNode.ip}</h2>
                <button type="button" onClick={() => setSelectedIp(null)}>
                  Clear focus
                </button>
              </div>
              <dl>
                <div>
                  <dt>Total data</dt>
                  <dd>{byteLabel(selectedNode.bytes)}</dd>
                </div>
                <div>
                  <dt>Packets</dt>
                  <dd>{selectedNode.packets.toLocaleString()}</dd>
                </div>
              </dl>
              <div className="focusSummary">
                <span>{selectedNeighborhood.oneHop.length} direct</span>
                <span>{visibleEdges.length} links</span>
              </div>
              {selectedNeighborhood.oneHop.length > 0 && (
                <div className="neighborList" aria-label="Direct neighbors">
                  {selectedNeighborhood.oneHop.slice(0, 8).map((ip) => (
                    <button type="button" key={ip} onClick={() => setSelectedIp(ip)}>
                      {ip}
                    </button>
                  ))}
                </div>
              )}
            </section>
          )}
        </aside>

        {activeTab === 'live' && (
        <aside
          className={isStatsDrawerOpen ? 'statsDrawer open' : 'statsDrawer'}
          aria-label="Live network statistics"
        >
          <div className="statsHeader">
            <div>
              <p>Network stats</p>
              <h2>{selectedNode ? selectedNode.ip : 'Whole network'}</h2>
            </div>
            <button type="button" onClick={() => setIsStatsDrawerOpen((open) => !open)}>
              {isStatsDrawerOpen ? 'Collapse' : 'Expand'}
            </button>
          </div>

          <div className="statsGrid">
            <section>
              <h3>Selected host</h3>
              {selectedNode ? (
                <dl>
                  <div>
                    <dt>Total data</dt>
                    <dd>{byteLabel(selectedNode.bytes)}</dd>
                  </div>
                  <div>
                    <dt>Packets</dt>
                    <dd>{selectedNode.packets.toLocaleString()}</dd>
                  </div>
                  <div>
                    <dt>Direct peers</dt>
                    <dd>{selectedNeighborhood.oneHop.length.toLocaleString()}</dd>
                  </div>
                  <div>
                    <dt>Active links</dt>
                    <dd>{visibleEdges.length.toLocaleString()}</dd>
                  </div>
                </dl>
              ) : (
                <p className="emptyText">Click a node to inspect host statistics.</p>
              )}
            </section>

            <section>
              <h3>Network summary</h3>
              <dl>
                <div>
                  <dt>Hosts</dt>
                  <dd>{networkStats.hosts.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>Links</dt>
                  <dd>{networkStats.links.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>Packets</dt>
                  <dd>{networkStats.totalPackets.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>Data</dt>
                  <dd>{byteLabel(networkStats.totalBytes)}</dd>
                </div>
              </dl>
            </section>

            <section>
              <h3>Top hosts</h3>
              <div className="statsRows">
                {nodes.slice(0, 6).map((node) => (
                  <button
                    className={node.ip === selectedIp ? 'statsRow selected' : 'statsRow'}
                    key={node.ip}
                    type="button"
                    onClick={() => setSelectedIp(node.ip)}
                  >
                    <span>{node.ip}</span>
                    <strong>{byteLabel(node.bytes)}</strong>
                  </button>
                ))}
                {nodes.length === 0 && (
                  <p className="emptyText">Start live capture or replay a PCAP to populate the map.</p>
                )}
              </div>
            </section>

            <section>
              <h3>Top conversations</h3>
              <div className="statsRows">
                {topConversations.map((edge) => (
                  <button
                    className="statsRow conversation"
                    key={edge.key}
                    type="button"
                    onClick={() => setSelectedIp(edge.src)}
                  >
                    <span>
                      {edge.src} to {edge.dst}
                    </span>
                    <strong>{byteLabel(edge.bytes)}</strong>
                  </button>
                ))}
                {topConversations.length === 0 && (
                  <p className="emptyText">Upload a capture, then press Play.</p>
                )}
              </div>
            </section>
          </div>
        </aside>
        )}

        {activeTab === 'replay' && replayMeta && (
          <aside
            className={isConversationRankOpen ? 'conversationRank open' : 'conversationRank'}
            aria-label="Conversations ranked by traffic"
          >
            <div className="rankHeader">
              <div>
                <p>Conversations</p>
                <h2>Ranked by data transferred</h2>
              </div>
              <select value={conversationSort} onChange={(event) => setConversationSort(event.target.value)}>
                <option value="bytes">Bytes</option>
                <option value="packets">Packets</option>
                <option value="rate">Rate</option>
                <option value="recent">Recent</option>
              </select>
              <button type="button" onClick={() => setIsConversationRankOpen((open) => !open)}>
                {isConversationRankOpen ? 'Collapse' : 'Expand'}
              </button>
            </div>
            <div className="rankRows">
              {replayAnalysis.conversations.slice(0, isConversationRankOpen ? 12 : 3).map((conversation) => (
                <button
                  className="rankRow"
                  key={conversation.key}
                  type="button"
                  onClick={() => setSelectedIp(conversation.src)}
                >
                  <span>{conversation.src} to {conversation.dst}</span>
                  <strong>{byteLabel(conversation.bytes)}</strong>
                  <em>{conversation.packets.toLocaleString()} pkts</em>
                </button>
              ))}
            </div>
          </aside>
        )}

        </section>
        {activeTab === 'instructions' && (
          <section className="tabPage" aria-label={`${TABS[activeTab]} tab`}>
            {activeTabContent[activeTab]}
          </section>
        )}
      </HeroAsciiOne>
    </main>
  )
}
