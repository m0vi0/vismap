import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
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

const PROTOCOLS = {
  TCP: { color: 0xf4f4f5, label: 'TCP' },
  UDP: { color: 0xb7b7bd, label: 'UDP' },
  DNS: { color: 0xd8d8dc, label: 'DNS' },
  OTHER: { color: 0x8b8b93, label: 'Other' },
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
  canvas.width = 512
  canvas.height = 128

  const ctx = canvas.getContext('2d')
  ctx.clearRect(0, 0, canvas.width, canvas.height)
  ctx.font = '600 34px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillStyle = 'rgba(6, 6, 7, 0.82)'
  ctx.fillRect(16, 30, 480, 68)
  ctx.strokeStyle = accent
  ctx.lineWidth = 3
  ctx.strokeRect(16, 30, 480, 68)
  ctx.fillStyle = '#f7fbfa'
  ctx.fillText(text, 256, 64)

  const texture = new THREE.CanvasTexture(canvas)
  texture.colorSpace = THREE.SRGBColorSpace
  const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: false })
  const sprite = new THREE.Sprite(material)
  sprite.scale.set(74, 18, 1)
  return sprite
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

  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [status, setStatus] = useState('connecting')
  const [captureMessage, setCaptureMessage] = useState('')
  const [captureInterface, setCaptureInterface] = useState('')
  const [selectedIp, setSelectedIp] = useState(null)
  const [isDeviceDrawerOpen, setIsDeviceDrawerOpen] = useState(false)

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

  useEffect(() => {
    selectedIpRef.current = selectedIp
  }, [selectedIp])

  useEffect(() => {
    const mount = mountRef.current
    const nodeStore = nodesRef.current
    const edgeStore = edgesRef.current
    const packetStore = packetsRef.current
    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x050505)

    const camera = new THREE.PerspectiveCamera(54, mount.clientWidth / mount.clientHeight, 0.1, 2200)
    camera.position.set(150, 130, 285)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(mount.clientWidth, mount.clientHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.outputColorSpace = THREE.SRGBColorSpace
    mount.appendChild(renderer.domElement)

    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.dampingFactor = 0.08
    controls.minDistance = 90
    controls.maxDistance = 760
    controls.screenSpacePanning = true

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
      ringGuides.forEach((guide, index) => {
        const ringIndex = index + 1
        const visible = hasFocus ? ringIndex === 1 : true
        guide.visible = visible
        if (visible) updateRingGuide(guide, ringRadii[ringIndex], ringIndex * -8)
      })

      ringLabels.forEach((label, ringIndex) => {
        const visible = hasFocus ? ringIndex <= 1 : true
        const radius = ringRadii[ringIndex] || 0
        label.visible = visible
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
        const depth = hasFocus ? depths.get(node.ip) : 0
        const visibleWeight = hasFocus
          ? { 0: 1, 1: 0.94 }[depth] || 0
          : 1
        const scale = (nodeRadius(node) / 8) * nodeRenderScale(node)
        const labelScale = THREE.MathUtils.clamp(nodeRenderScale(node), 0.55, 1)
        const pulse = THREE.MathUtils.clamp(node.recentBytes / 4500, 0, 1.8)
        node.group.position.set(node.x, node.y, node.z)
        node.mesh.scale.lerp(new THREE.Vector3(scale + pulse, scale + pulse, scale + pulse), 0.18)
        node.mesh.material.opacity = THREE.MathUtils.lerp(node.mesh.material.opacity, visibleWeight, 0.12)
        node.label.material.opacity = THREE.MathUtils.lerp(
          node.label.material.opacity,
          hasFocus && depth === undefined ? 0 : Math.max(visibleWeight, 0.72),
          0.14,
        )
        node.label.position.y = 18 + scale * 6
        node.label.scale.lerp(new THREE.Vector3(74 * labelScale, 18 * labelScale, 1), 0.18)
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

    function animate() {
      frameRef.current = requestAnimationFrame(animate)
      controls.update()
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

    function handleResize() {
      camera.aspect = mount.clientWidth / mount.clientHeight
      camera.updateProjectionMatrix()
      renderer.setSize(mount.clientWidth, mount.clientHeight)
    }

    renderer.domElement.addEventListener('pointerdown', handlePointerDown)
    window.addEventListener('resize', handleResize)
    animate()

    const ws = new WebSocket(WS_URL)
    websocketRef.current = ws
    ws.addEventListener('open', () => {
      setStatus('ready')
    })

    ws.addEventListener('message', (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'packet') ingestPacket(data)
      if (data.type === 'nodes') applyNodeSummary(data.nodes || [])
      if (data.type === 'capture_status') {
        setCaptureInterface(data.iface || '')
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
      controls.dispose()

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
      renderer.dispose()

      if (mount.contains(renderer.domElement)) {
        mount.removeChild(renderer.domElement)
      }
    }
  }, [])

  function requestCapture() {
    if (websocketRef.current?.readyState !== WebSocket.OPEN) {
      setStatus('offline')
      return
    }

    setStatus('starting')
    websocketRef.current.send(JSON.stringify({ type: 'start_capture' }))
  }

  const needsCapturePermission = status === 'ready' || status === 'capture_error'

  return (
    <main className="appShell">
      <HeroAsciiOne>
        <section className="viewport" aria-label="3D packet tracer">
        <div ref={mountRef} className="canvasMount" />

        <header className="topBar" aria-label="App status">
          <div className="brandBlock">
            <p>pacmap</p>
          </div>
        </header>

        {needsCapturePermission && (
          <section className="permissionPanel" aria-label="Start host packet capture">
            <p className="permissionKicker">Local permission</p>
            <h2>Start host capture?</h2>
            <p>
              pacmap will ask the local Python helper to capture IP packets on
              {captureInterface ? ` ${captureInterface}` : ' the configured interface'}.
              Browsers cannot grant raw packet access directly, so this prompt starts the
              trusted local helper.
            </p>
            {captureMessage && <p className="permissionError">{captureMessage}</p>}
            <button type="button" onClick={requestCapture}>
              Start host capture
            </button>
          </section>
        )}

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

        </section>
      </HeroAsciiOne>
    </main>
  )
}
