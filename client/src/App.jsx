import { useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import AetherFlowHero from './components/ui/aether-flow-hero.jsx'
import './App.css'

const WS_URL = 'ws://127.0.0.1:8765'
const MAX_PACKET_PARTICLES = 420
const NODE_LIMIT = 18

const PROTOCOLS = {
  TCP: { color: 0x36e4ff, label: 'TCP' },
  UDP: { color: 0xff5ab8, label: 'UDP' },
  DNS: { color: 0x50f2a4, label: 'DNS' },
  OTHER: { color: 0xffc857, label: 'Other' },
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

function makeTextSprite(text, accent = '#36e4ff') {
  const canvas = document.createElement('canvas')
  canvas.width = 512
  canvas.height = 128

  const ctx = canvas.getContext('2d')
  ctx.clearRect(0, 0, canvas.width, canvas.height)
  ctx.font = '600 34px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillStyle = 'rgba(3, 8, 10, 0.78)'
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

function createGridTexture() {
  const canvas = document.createElement('canvas')
  canvas.width = 512
  canvas.height = 512
  const ctx = canvas.getContext('2d')

  ctx.fillStyle = '#030506'
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  ctx.strokeStyle = 'rgba(54, 228, 255, 0.12)'
  ctx.lineWidth = 1

  for (let i = 0; i <= 512; i += 32) {
    ctx.beginPath()
    ctx.moveTo(i, 0)
    ctx.lineTo(i, 512)
    ctx.stroke()
    ctx.beginPath()
    ctx.moveTo(0, i)
    ctx.lineTo(512, i)
    ctx.stroke()
  }

  const texture = new THREE.CanvasTexture(canvas)
  texture.wrapS = THREE.RepeatWrapping
  texture.wrapT = THREE.RepeatWrapping
  texture.repeat.set(6, 6)
  return texture
}

export default function App() {
  const mountRef = useRef(null)
  const nodesRef = useRef(new Map())
  const edgesRef = useRef(new Map())
  const packetsRef = useRef([])
  const frameRef = useRef(0)
  const websocketRef = useRef(null)

  const [nodes, setNodes] = useState([])
  const [edges, setEdges] = useState([])
  const [status, setStatus] = useState('connecting')
  const [captureMessage, setCaptureMessage] = useState('')
  const [captureInterface, setCaptureInterface] = useState('')
  const [totalPackets, setTotalPackets] = useState(0)
  const [selectedIp, setSelectedIp] = useState(null)

  const selectedNode = useMemo(
    () => nodes.find((node) => node.ip === selectedIp),
    [nodes, selectedIp],
  )

  useEffect(() => {
    const mount = mountRef.current
    const nodeStore = nodesRef.current
    const edgeStore = edgesRef.current
    const packetStore = packetsRef.current
    const scene = new THREE.Scene()
    scene.background = null

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

    scene.add(new THREE.HemisphereLight(0xe9fff9, 0x11221f, 2.6))
    scene.add(new THREE.AmbientLight(0xffffff, 1.35))
    const keyLight = new THREE.DirectionalLight(0xffffff, 1.8)
    keyLight.position.set(220, 260, 160)
    scene.add(keyLight)
    const rimLight = new THREE.PointLight(0xffc857, 2.2, 600)
    rimLight.position.set(-180, -80, -120)
    scene.add(rimLight)

    const gridTexture = createGridTexture()
    const grid = new THREE.Mesh(
      new THREE.PlaneGeometry(900, 900),
      new THREE.MeshStandardMaterial({
        map: gridTexture,
        color: 0x283332,
        roughness: 0.82,
        metalness: 0.08,
        transparent: true,
        opacity: 0.55,
      }),
    )
    grid.rotation.x = -Math.PI / 2
    grid.position.y = -105
    scene.add(grid)

    const nodeGeometry = new THREE.SphereGeometry(8, 32, 24)
    const edgeGeometry = new THREE.CylinderGeometry(1, 1, 1, 10)
    const packetGeometry = new THREE.SphereGeometry(2.5, 12, 12)
    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2()

    function snapshotState() {
      const nextNodes = [...nodeStore.values()]
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
        color: 0x7df7ff,
        emissive: 0x1eb8c7,
        emissiveIntensity: 0.38,
        roughness: 0.48,
        metalness: 0.18,
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
        vx: 0,
        vy: 0,
        vz: 0,
        bytes: 0,
        packets: 0,
        recentBytes: 0,
      }

      nodeStore.set(ip, node)
      snapshotState()
      return node
    }

    function ensureEdge(src, dst) {
      const key = edgeKey(src, dst)
      if (edgeStore.has(key)) return edgeStore.get(key)

      const material = new THREE.MeshBasicMaterial({
        color: 0x36e4ff,
        transparent: true,
        opacity: 0.34,
      })
      const mesh = new THREE.Mesh(edgeGeometry, material)
      scene.add(mesh)

      const edge = { key, src, dst, mesh, bytes: 0, packets: 0, recentBytes: 0 }
      edgeStore.set(key, edge)
      snapshotState()
      return edge
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
      setTotalPackets((count) => count + 1)
    }

    function applyNodeSummary(summaryNodes) {
      summaryNodes.forEach((summary) => {
        const node = ensureNode(summary.ip)
        node.bytes = Math.max(node.bytes, Number(summary.bytes) || 0)
        node.packets = Math.max(node.packets, Number(summary.packets) || 0)
      })
      snapshotState()
    }

    function simulateForces() {
      const nodeList = [...nodeStore.values()]
      const edgeList = [...edgeStore.values()]
      if (nodeList.length < 2) return

      for (let i = 0; i < nodeList.length; i += 1) {
        for (let j = i + 1; j < nodeList.length; j += 1) {
          const a = nodeList[i]
          const b = nodeList[j]
          const dx = b.x - a.x
          const dy = b.y - a.y
          const dz = b.z - a.z
          const distSq = Math.max(dx * dx + dy * dy + dz * dz, 80)
          const dist = Math.sqrt(distSq)
          const force = 1850 / distSq
          const fx = (dx / dist) * force
          const fy = (dy / dist) * force
          const fz = (dz / dist) * force

          a.vx -= fx
          a.vy -= fy
          a.vz -= fz
          b.vx += fx
          b.vy += fy
          b.vz += fz
        }
      }

      edgeList.forEach((edge) => {
        const a = nodeStore.get(edge.src)
        const b = nodeStore.get(edge.dst)
        if (!a || !b) return

        const dx = b.x - a.x
        const dy = b.y - a.y
        const dz = b.z - a.z
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1
        const preferred = 105 + Math.min(Math.log10(edge.bytes + 1) * 9, 55)
        const force = 0.011 * (dist - preferred)
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        const fz = (dz / dist) * force

        a.vx += fx
        a.vy += fy
        a.vz += fz
        b.vx -= fx
        b.vy -= fy
        b.vz -= fz
      })

      nodeList.forEach((node) => {
        node.vx *= 0.86
        node.vy *= 0.86
        node.vz *= 0.86
        node.x += node.vx
        node.y += node.vy
        node.z += node.vz

        const scale = THREE.MathUtils.clamp(1 + Math.log10(node.bytes + 1) * 0.18, 1, 3.8)
        const pulse = THREE.MathUtils.clamp(node.recentBytes / 4500, 0, 1.8)
        node.group.position.set(node.x, node.y, node.z)
        node.mesh.scale.lerp(new THREE.Vector3(scale + pulse, scale + pulse, scale + pulse), 0.18)
        node.label.position.y = 18 + scale * 6
        node.recentBytes *= 0.91
      })

      edgeList.forEach((edge) => {
        const a = nodeStore.get(edge.src)
        const b = nodeStore.get(edge.dst)
        if (!a || !b) return

        const start = new THREE.Vector3(a.x, a.y, a.z)
        const end = new THREE.Vector3(b.x, b.y, b.z)
        const radius = THREE.MathUtils.clamp(0.36 + Math.log10(edge.bytes + 1) * 0.13, 0.36, 2.35)
        edge.mesh.material.opacity = THREE.MathUtils.clamp(0.23 + edge.recentBytes / 5500, 0.23, 0.86)
        setCylinderBetween(edge.mesh, start, end, radius)
        edge.recentBytes *= 0.88
      })
    }

    function updatePackets() {
      const remove = []

      packetStore.forEach((packet, index) => {
        const src = nodeStore.get(packet.src)
        const dst = nodeStore.get(packet.dst)
        if (!src || !dst) {
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
      })

      remove.reverse().forEach((index) => packetStore.splice(index, 1))
    }

    function animate() {
      frameRef.current = requestAnimationFrame(animate)
      controls.update()
      simulateForces()
      updatePackets()

      nodeStore.forEach((node) => {
        node.label.quaternion.copy(camera.quaternion)
      })

      if (Math.random() < 0.03) snapshotState()
      renderer.render(scene, camera)
    }

    function handlePointerDown(event) {
      const bounds = renderer.domElement.getBoundingClientRect()
      pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1
      pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1
      raycaster.setFromCamera(pointer, camera)
      const meshes = [...nodeStore.values()].map((node) => node.mesh)
      const hit = raycaster.intersectObjects(meshes, false)[0]
      if (hit?.object?.userData?.ip) {
        setSelectedIp(hit.object.userData.ip)
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
      gridTexture.dispose()
      renderer.dispose()

      if (mount.contains(renderer.domElement)) {
        mount.removeChild(renderer.domElement)
      }
    }
  }, [])

  const statusText = {
    connecting: 'Connecting',
    ready: 'Ready',
    starting: 'Starting capture',
    live: 'Live capture',
    capture_error: 'Capture blocked',
    offline: 'Capture server offline',
  }[status]

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
      <AetherFlowHero
        title="VISMAP"
        badge="Host Packet Flow"
        actionLabel="Browser-gated capture"
        description="A live packet tracer with clean 3D nodes, direct edge paths, and host network traffic after you approve capture locally."
      >
      <section className="viewport" aria-label="3D packet tracer">
        <div ref={mountRef} className="canvasMount" />

        <header className="topBar" aria-label="Capture status">
          <div className={`statusPill status-${status}`}>
            <span />
            {statusText}
          </div>
        </header>

        {needsCapturePermission && (
          <section className="permissionPanel" aria-label="Start host packet capture">
            <p className="permissionKicker">Local permission</p>
            <h2>Start host capture?</h2>
            <p>
              VISMAP will ask the local Python helper to capture IP packets on
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

        <aside className="hud" aria-label="Network traffic summary">
          <div className="statGrid">
            <div>
              <span>Packets</span>
              <strong>{totalPackets.toLocaleString()}</strong>
            </div>
            <div>
              <span>Devices</span>
              <strong>{nodes.length}</strong>
            </div>
            <div>
              <span>Links</span>
              <strong>{edges.length}</strong>
            </div>
          </div>

          <section className="panel">
            <div className="panelTitle">
              <h2>Largest Devices</h2>
              <span>by data</span>
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
                <p className="emptyText">Click Start host capture, then use the network normally.</p>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panelTitle">
              <h2>Strongest Links</h2>
              <span>by bytes</span>
            </div>
            <div className="linkList">
              {edges.slice(0, 6).map((edge) => (
                <div className="linkRow" key={edge.key}>
                  <span>{edge.src}</span>
                  <span>{edge.dst}</span>
                  <strong>{byteLabel(edge.bytes)}</strong>
                </div>
              ))}
              {edges.length === 0 && (
                <p className="emptyText">Links appear when two devices communicate.</p>
              )}
            </div>
          </section>

          {selectedNode && (
            <section className="panel selectedPanel">
              <div className="panelTitle">
                <h2>{selectedNode.ip}</h2>
                <span>selected</span>
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
            </section>
          )}
        </aside>

        <footer className="legend">
          {Object.entries(PROTOCOLS).map(([key, protocol]) => (
            <span key={key}>
              <i style={{ backgroundColor: `#${protocol.color.toString(16).padStart(6, '0')}` }} />
              {protocol.label}
            </span>
          ))}
          <strong>Drag to orbit. Scroll to zoom. Click a node to inspect.</strong>
        </footer>
      </section>
      </AetherFlowHero>
    </main>
  )
}
