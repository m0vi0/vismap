const MEDIAPIPE_CDN = 'https://cdn.jsdelivr.net/npm/@mediapipe/hands/hands.js'
const CAMERA_CDN = 'https://cdn.jsdelivr.net/npm/@mediapipe/camera_utils/camera_utils.js'

const INDEX_TIP = 8
const THUMB_TIP = 4
const MIDDLE_TIP = 12
const RING_TIP = 16
const PINKY_TIP = 20
const INDEX_PIP = 6
const MIDDLE_PIP = 10
const RING_PIP = 14
const PINKY_PIP = 18
const PREVIEW_WIDTH = 320
const PREVIEW_HEIGHT = 180
const POINT_SMOOTHING = 0.34
const CONTROL_SMOOTHING = 0.24
const ORBIT_DAMPING = 0.86
const SPREAD_DAMPING = 0.82
const TAP_CLOSE_DISTANCE = 0.055
const TAP_OPEN_DISTANCE = 0.095
const TAP_RESOLVE_MS = 650
const TAP_MAX_DOWN_MS = 900
const DEBUG_TAPS = false
const MODE_COOLDOWN_MS = 360
const ZOOM_DEPTH_THRESHOLD = 0.0038
const ROTATE_DISTANCE_THRESHOLD = 0.0055
const ROTATE_ANGLE_THRESHOLD = 0.026
const ROTATE_LOCK_DISTANCE_UNIT = 0.07
const ROTATE_LOCK_ANGLE_UNIT = 0.3
const PAN_MIDPOINT_THRESHOLD = 0.006
const LOCK_STABLE_MS = 1000
const LOCK_PROGRESS_MS = 500
const LOCK_STABILITY_TOLERANCE = 1
const LOCK_DISTANCE_UNIT = 0.045
const LOCK_ANGLE_UNIT = 0.18
const LOCK_DEPTH_UNIT = 0.075
const LOCK_MIDPOINT_UNIT = 0.13
const OPEN_HAND_SPREAD = 0.18
const OPEN_HAND_COOLDOWN_MS = 650
const MIN_LAYOUT_SPREAD = 0.5
const MAX_LAYOUT_SPREAD = 2.25
const PAN_BOUND = 320
function dist2d(a, b) {
    return Math.sqrt((a.x - b.x) ** 2 + (a.y - b.y) ** 2)
}

function angleDelta(next, previous) {
    let delta = next - previous
    while (delta > Math.PI) delta -= Math.PI * 2
    while (delta < -Math.PI) delta += Math.PI * 2
    return delta
}

function thumbIndexControl(landmarks) {
    const thumb = landmarks[THUMB_TIP]
    const index = landmarks[INDEX_TIP]
    const distance = dist2d(thumb, index)
    const angle = Math.atan2(index.y - thumb.y, index.x - thumb.x)
    const midpoint = {
        x: (thumb.x + index.x) * 0.5,
        y: (thumb.y + index.y) * 0.5,
    }
    const depth = ((thumb.z || 0) + (index.z || 0)) * 0.5

    return { thumb, index, distance, angle, midpoint, depth }
}

function smoothControl(previous, next) {
    if (!previous) return next

    const smoothPoint = (a, b) => ({
        x: a.x + (b.x - a.x) * CONTROL_SMOOTHING,
        y: a.y + (b.y - a.y) * CONTROL_SMOOTHING,
        z: (a.z || 0) + ((b.z || 0) - (a.z || 0)) * CONTROL_SMOOTHING,
    })

    return {
        thumb: smoothPoint(previous.thumb, next.thumb),
        index: smoothPoint(previous.index, next.index),
        distance: previous.distance + (next.distance - previous.distance) * CONTROL_SMOOTHING,
        angle: previous.angle + angleDelta(next.angle, previous.angle) * CONTROL_SMOOTHING,
        midpoint: smoothPoint(previous.midpoint, next.midpoint),
        depth: previous.depth + (next.depth - previous.depth) * CONTROL_SMOOTHING,
    }
}

function isInFrame(control) {
    return [control.thumb, control.index].every((point) =>
        point.x >= -0.08 &&
        point.x <= 1.08 &&
        point.y >= -0.08 &&
        point.y <= 1.08
    )
}

function isFingerExtended(landmarks, tipIndex, pipIndex) {
    return landmarks[tipIndex].y < landmarks[pipIndex].y - 0.025
}

function isOpenHand(landmarks) {
    const thumb = landmarks[THUMB_TIP]
    const index = landmarks[INDEX_TIP]
    const pinky = landmarks[PINKY_TIP]
    const fingersExtended =
        isFingerExtended(landmarks, INDEX_TIP, INDEX_PIP) &&
        isFingerExtended(landmarks, MIDDLE_TIP, MIDDLE_PIP) &&
        isFingerExtended(landmarks, RING_TIP, RING_PIP) &&
        isFingerExtended(landmarks, PINKY_TIP, PINKY_PIP)

    return fingersExtended &&
        dist2d(index, pinky) >= OPEN_HAND_SPREAD &&
        dist2d(thumb, index) >= TAP_OPEN_DISTANCE
}

export function useHandGestures({ orbitStateRef, applyOrbitRef, cameraRef, layoutSpreadRef, onPointAt }) {
    const modeRef = { current: 'zoom' }
    const previousControlRef = { current: null }
    const smoothedControlRef = { current: null }
    const smoothedPointRef = { current: null }
    const orbitVelocityRef = { current: { theta: 0, phi: 0, spread: 0, targetX: 0, targetY: 0, targetZ: 0 } }
    const pointActiveRef = { current: false }
    const pinchDownRef = { current: false }
    const tapDownStartedAtRef = { current: 0 }
    const tapCountRef = { current: 0 }
    const modeCooldownUntilRef = { current: 0 }
    const openHandCooldownUntilRef = { current: 0 }
    const lockRef = { current: initialLockState() }

    if (typeof window === 'undefined') return

    let handsInstance = null
    let mpCamera = null
    let video = null
    let canvas = null
    let ctx = null
    let active = false
    let momentumFrame = null
    let tapTimer = null

    function loadScript(src) {
        return new Promise((resolve) => {
            if (document.querySelector(`script[src="${src}"]`)) { resolve(); return }
            const s = document.createElement('script')
            s.src = src
            s.crossOrigin = 'anonymous'
            s.onload = resolve
            document.head.appendChild(s)
        })
    }

    // Return a useEffect-compatible setup — caller must use this inside useEffect
    return async function init() {
        active = true
        await loadScript(MEDIAPIPE_CDN)
        await loadScript(CAMERA_CDN)
        if (!active) return

        video = document.createElement('video')
        video.style.cssText = `
      position: fixed; bottom: 16px; right: 16px;
      width: 320px; height: 180px; border-radius: 8px;
      opacity: 0.5; z-index: 9999; transform: scaleX(-1);
      border: 1px solid rgba(255,255,255,0.1);
    `
        video.autoplay = true
        video.muted = true
        video.playsInline = true
        document.body.appendChild(video)

        canvas = document.createElement('canvas')
        canvas.width = PREVIEW_WIDTH
        canvas.height = PREVIEW_HEIGHT
        canvas.style.cssText = `
      position: fixed; bottom: 16px; right: 16px;
      width: 320px; height: 180px; border-radius: 8px;
      z-index: 10000; pointer-events: none;
    `
        ctx = canvas.getContext('2d')
        document.body.appendChild(canvas)

        // eslint-disable-next-line no-undef
        handsInstance = new Hands({
            locateFile: (file) => `https://cdn.jsdelivr.net/npm/@mediapipe/hands/${file}`,
        })

        handsInstance.setOptions({
            maxNumHands: 1,
            modelComplexity: 1,
            minDetectionConfidence: 0.7,
            minTrackingConfidence: 0.6,
        })

        handsInstance.onResults((results) => {
            if (!results.multiHandLandmarks?.length) {
                handleTrackingLoss()
                drawHandOverlay([], modeRef.current)
                return
            }

            const landmarks = results.multiHandLandmarks[0]
            const rawControl = thumbIndexControl(landmarks)
            const control = smoothControl(smoothedControlRef.current, rawControl)
            smoothedControlRef.current = control
            const now = performance.now()
            const orbit = orbitStateRef?.current
            if (!isInFrame(rawControl)) {
                handleTrackingLoss()
                drawHandOverlay(landmarks, modeRef.current)
                return
            }
            if (orbit) orbit.recenterPan = false

            if (modeRef.current === 'pointer' && now >= openHandCooldownUntilRef.current && isOpenHand(landmarks)) {
                openHandCooldownUntilRef.current = now + OPEN_HAND_COOLDOWN_MS
                clearPendingTaps()
                resetLock()
                drawHandOverlay(landmarks, modeRef.current)
                emitPointer(control, { openHand: true })
                previousControlRef.current = control
                pointActiveRef.current = true
                return
            }

            handleModeTap(control, now)
            drawHandOverlay(landmarks, modeRef.current)

            if (now < modeCooldownUntilRef.current) {
                emitPointer(control)
                previousControlRef.current = control
                return
            }

            if (modeRef.current !== 'pointer' && orbit && previousControlRef.current) {
                applyModeGesture(control, previousControlRef.current)
                updateModeLock(control, now)
            }

            if (modeRef.current === 'pointer') {
                if (!hasPendingTap()) {
                    updateModeLock(control, now)
                } else {
                    resetLock()
                }
            }

            const lock = lockRef.current
            const pointerSelectionComplete = modeRef.current === 'pointer' && lock.completed
            emitPointer(control, { selectionLockComplete: pointerSelectionComplete })

            if (lock.completed) {
                if (modeRef.current === 'pointer') {
                    resetLock()
                    previousControlRef.current = control
                    pointActiveRef.current = true
                    return
                }
                transitionTo('pointer', now)
                previousControlRef.current = control
                return
            }

            if (modeRef.current === 'pointer') {
                if (!pointActiveRef.current) {
                    zeroOrbitVelocity()
                }
                pointActiveRef.current = true
            }

            previousControlRef.current = control
        })

        // eslint-disable-next-line no-undef
        mpCamera = new Camera(video, {
            onFrame: async () => {
                if (handsInstance) await handsInstance.send({ image: video })
            },
            width: 320,
            height: 180,
        })
        mpCamera.start()

        return function cleanup() {
            active = false
            onPointAt?.({ active: false, lockKind: null, lockProgress: 0, locked: false })
            if (momentumFrame !== null) {
                window.cancelAnimationFrame(momentumFrame)
                momentumFrame = null
            }
            if (tapTimer !== null) {
                window.clearTimeout(tapTimer)
                tapTimer = null
            }
            mpCamera?.stop()
            handsInstance?.close()
            if (video) {
                video.srcObject?.getTracks().forEach(t => t.stop())
                video.remove()
            }
            canvas?.remove()
        }
    }

    function debugTap(...args) {
        if (DEBUG_TAPS) console.debug('[pacmap taps]', ...args)
    }

    function hasPendingTap() {
        return pinchDownRef.current || tapCountRef.current > 0 || tapTimer !== null
    }

    function handleModeTap(control, now) {
        if (modeRef.current !== 'pointer') return

        if (pinchDownRef.current && now - tapDownStartedAtRef.current > TAP_MAX_DOWN_MS) {
            debugTap('cancel long press')
            pinchDownRef.current = false
            tapDownStartedAtRef.current = 0
        }

        if (!pinchDownRef.current && control.distance <= TAP_CLOSE_DISTANCE) {
            pinchDownRef.current = true
            tapDownStartedAtRef.current = now
            resetLock()
            debugTap('tap start')
            return
        }

        if (!pinchDownRef.current || control.distance < TAP_OPEN_DISTANCE) return

        pinchDownRef.current = false
        tapDownStartedAtRef.current = 0

        tapCountRef.current += 1
        resetLock()
        debugTap('tap end', { count: tapCountRef.current })
        if (tapTimer !== null) window.clearTimeout(tapTimer)
        tapTimer = window.setTimeout(() => {
            const taps = tapCountRef.current
            tapCountRef.current = 0
            tapTimer = null

            if (taps >= 3) {
                debugTap('resolve triple -> move')
                transitionTo('move', performance.now())
                return
            }
            if (taps === 2) {
                debugTap('resolve double -> zoom')
                transitionTo('zoom', performance.now())
                return
            }
            debugTap('resolve single -> rotate')
            transitionTo('rotate', performance.now())
        }, TAP_RESOLVE_MS)
    }

    function clearPendingTaps() {
        if (tapTimer !== null) {
            window.clearTimeout(tapTimer)
            tapTimer = null
        }
        tapCountRef.current = 0
        pinchDownRef.current = false
        tapDownStartedAtRef.current = 0
    }

    function transitionTo(mode, now) {
        const wasPointer = modeRef.current === 'pointer'
        modeRef.current = mode
        previousControlRef.current = null
        smoothedControlRef.current = null
        smoothedPointRef.current = null
        resetLock()
        modeCooldownUntilRef.current = now + MODE_COOLDOWN_MS
        zeroOrbitVelocity()

        if (tapTimer !== null && mode !== 'pointer') {
            window.clearTimeout(tapTimer)
            tapTimer = null
            tapCountRef.current = 0
        }

        if (wasPointer && mode !== 'pointer') {
            onPointAt?.({ active: false, lockKind: null, lockProgress: 0, locked: false })
            pointActiveRef.current = false
        }
    }

    function handleTrackingLoss() {
        if (modeRef.current === 'pointer') {
            debugTap('tracking loss preserved in pointer')
            return
        }

        previousControlRef.current = null
        smoothedControlRef.current = null
        pinchDownRef.current = false
        tapDownStartedAtRef.current = 0

        smoothedPointRef.current = null
        resetLock()
        beginPanReturn()
        onPointAt?.({ active: false, lockKind: null, lockProgress: 0, locked: false })
        pointActiveRef.current = false
    }

    function initialLockState() {
        return {
            kind: null,
            baseline: null,
            stableStartedAt: null,
            progressStartedAt: null,
            progress: 0,
            completed: false,
        }
    }

    function resetLock() {
        lockRef.current = initialLockState()
    }

    function updateModeLock(control, now) {
        const lock = lockRef.current
        const baseline = lock.baseline
        const mode = modeRef.current

        if (!baseline || lock.kind !== mode) {
            lockRef.current = {
                ...initialLockState(),
                kind: mode,
                baseline: control,
                stableStartedAt: now,
            }
            return
        }

        const unstable = modeIsUnstable(mode, control, baseline)

        if (unstable) {
            lockRef.current = {
                ...initialLockState(),
                kind: mode,
                baseline: control,
                stableStartedAt: now,
            }
            return
        }

        if (now - lock.stableStartedAt < LOCK_STABLE_MS) {
            lock.progressStartedAt = null
            lock.progress = 0
            return
        }

        if (lock.progressStartedAt === null) lock.progressStartedAt = now

        lock.progress = Math.min((now - lock.progressStartedAt) / LOCK_PROGRESS_MS, 1)
        lock.completed = lock.progress >= 1
    }

    function modeIsUnstable(mode, control, baseline) {
        return stableScore(mode, control, baseline) > LOCK_STABILITY_TOLERANCE
    }

    function stableScore(mode, control, baseline) {
        const midpointScore = dist2d(control.midpoint, baseline.midpoint) / LOCK_MIDPOINT_UNIT
        if (mode === 'zoom') {
            return Math.max(midpointScore, Math.abs(control.depth - baseline.depth) / LOCK_DEPTH_UNIT)
        }
        if (mode === 'move') {
            return Math.max(
                midpointScore,
                Math.abs(control.distance - baseline.distance) / (LOCK_DISTANCE_UNIT * 1.25),
            )
        }
        if (mode === 'rotate') {
            return Math.max(
                midpointScore,
                Math.abs(control.distance - baseline.distance) / ROTATE_LOCK_DISTANCE_UNIT,
                Math.abs(angleDelta(control.angle, baseline.angle)) / ROTATE_LOCK_ANGLE_UNIT,
            )
        }
        if (mode === 'pointer') {
            return Math.max(
                dist2d(control.index, baseline.index) / LOCK_MIDPOINT_UNIT,
                midpointScore,
                Math.abs(control.distance - baseline.distance) / (LOCK_DISTANCE_UNIT * 1.4),
            )
        }
        return 0
    }

    function zeroOrbitVelocity() {
        orbitVelocityRef.current.theta = 0
        orbitVelocityRef.current.phi = 0
        orbitVelocityRef.current.spread = 0
        orbitVelocityRef.current.targetX = 0
        orbitVelocityRef.current.targetY = 0
        orbitVelocityRef.current.targetZ = 0
    }

    function beginPanReturn() {
        const orbit = orbitStateRef?.current
        if (orbit) orbit.recenterPan = true
        zeroOrbitVelocity()
    }

    function applyModeGesture(control, previous) {
        if (modeRef.current === 'zoom') applyZoomGesture(control, previous)
        if (modeRef.current === 'rotate') applyRotateGesture(control, previous)
        if (modeRef.current === 'move') applyMoveGesture(control, previous)
    }

    function applyZoomGesture(control, previous) {
        const depthDelta = control.depth - previous.depth

        if (Math.abs(depthDelta) < ZOOM_DEPTH_THRESHOLD) return

        orbitVelocityRef.current.spread += -depthDelta * 10.5
        resetLock()
        startMomentumLoop()
    }

    function applyRotateGesture(control, previous) {
        const distanceDelta = control.distance - previous.distance
        const angleChange = angleDelta(control.angle, previous.angle)
        let changed = false

        if (Math.abs(distanceDelta) >= ROTATE_DISTANCE_THRESHOLD) {
            orbitVelocityRef.current.theta += distanceDelta * 2.35
            changed = true
        }

        if (Math.abs(angleChange) >= ROTATE_ANGLE_THRESHOLD) {
            orbitVelocityRef.current.phi += angleChange * 0.52
            changed = true
        }

        if (changed) {
            resetLock()
            startMomentumLoop()
        }
    }

    function applyMoveGesture(control, previous) {
        const midpointDelta = {
            x: control.midpoint.x - previous.midpoint.x,
            y: control.midpoint.y - previous.midpoint.y,
        }
        if (Math.hypot(midpointDelta.x, midpointDelta.y) < PAN_MIDPOINT_THRESHOLD) return

        applyPanVelocity(midpointDelta)
        resetLock()
        startMomentumLoop()
    }

    function applyPanVelocity(delta) {
        const camera = cameraRef?.current
        if (!camera) return

        const elements = camera.matrixWorld.elements
        const right = { x: elements[0], y: elements[1], z: elements[2] }
        const up = { x: elements[4], y: elements[5], z: elements[6] }
        const amountX = delta.x * 520
        const amountY = delta.y * 520

        orbitVelocityRef.current.targetX += right.x * amountX + up.x * amountY
        orbitVelocityRef.current.targetY += right.y * amountX + up.y * amountY
        orbitVelocityRef.current.targetZ += right.z * amountX + up.z * amountY
    }

    function emitPointer(control, options = {}) {
        const rawPoint = {
            x: (1 - control.index.x) * 2 - 1,
            y: -control.index.y * 2 + 1,
        }
        const previous = smoothedPointRef.current || rawPoint
        const smoothedPoint = {
            x: previous.x + (rawPoint.x - previous.x) * POINT_SMOOTHING,
            y: previous.y + (rawPoint.y - previous.y) * POINT_SMOOTHING,
        }
        smoothedPointRef.current = smoothedPoint

        const lock = lockRef.current
        onPointAt?.({
            active: true,
            mode: modeRef.current,
            x: smoothedPoint.x,
            y: smoothedPoint.y,
            lockKind: lock.kind,
            lockProgress: lock.progress,
            locked: lock.completed,
            selectionLockComplete: Boolean(options.selectionLockComplete),
            openHand: Boolean(options.openHand),
        })
    }

    function startMomentumLoop() {
        if (momentumFrame !== null) return

        function step() {
            momentumFrame = null
            if (!active) return

            const orbit = orbitStateRef?.current
            const applyOrbit = applyOrbitRef?.current
            const velocity = orbitVelocityRef.current
            if (!orbit || !applyOrbit) return

            orbit.panX = Math.max(-PAN_BOUND, Math.min(PAN_BOUND, (orbit.panX || 0) + velocity.targetX))
            orbit.panY = Math.max(-PAN_BOUND, Math.min(PAN_BOUND, (orbit.panY || 0) + velocity.targetY))
            orbit.panZ = Math.max(-PAN_BOUND, Math.min(PAN_BOUND, (orbit.panZ || 0) + velocity.targetZ))
            orbit.target.x += velocity.targetX
            orbit.target.y += velocity.targetY
            orbit.target.z += velocity.targetZ
            orbit.theta += velocity.theta
            orbit.phi = Math.max(0.08, Math.min(Math.PI - 0.08, orbit.phi + velocity.phi))
            if (layoutSpreadRef?.current) {
                layoutSpreadRef.current.target = Math.max(
                    MIN_LAYOUT_SPREAD,
                    Math.min(MAX_LAYOUT_SPREAD, layoutSpreadRef.current.target + velocity.spread),
                )
            }
            applyOrbit()

            velocity.theta *= ORBIT_DAMPING
            velocity.phi *= ORBIT_DAMPING
            velocity.spread *= SPREAD_DAMPING
            velocity.targetX *= ORBIT_DAMPING
            velocity.targetY *= ORBIT_DAMPING
            velocity.targetZ *= ORBIT_DAMPING

            const moving =
                Math.abs(velocity.theta) > 0.0008 ||
                Math.abs(velocity.phi) > 0.0008 ||
                Math.abs(velocity.spread) > 0.0008 ||
                Math.abs(velocity.targetX) > 0.04 ||
                Math.abs(velocity.targetY) > 0.04 ||
                Math.abs(velocity.targetZ) > 0.04

            if (moving) momentumFrame = window.requestAnimationFrame(step)
        }

        momentumFrame = window.requestAnimationFrame(step)
    }

    function pointFor(landmark) {
        return {
            x: (1 - landmark.x) * PREVIEW_WIDTH,
            y: landmark.y * PREVIEW_HEIGHT,
        }
    }

    function gestureLabel(mode) {
        if (mode === 'zoom') return 'Mode: Zoom'
        if (mode === 'rotate') return 'Mode: Rotate'
        if (mode === 'move') return 'Mode: Move'
        return 'Mode: Pointer'
    }

    function drawHandOverlay(landmarks, mode) {
        if (!ctx) return
        ctx.clearRect(0, 0, PREVIEW_WIDTH, PREVIEW_HEIGHT)

        ctx.fillStyle = 'rgba(5, 5, 5, 0.62)'
        ctx.fillRect(8, 8, 118, 24)
        ctx.fillStyle = '#f4f4f5'
        ctx.font = '700 12px ui-sans-serif, system-ui, sans-serif'
        ctx.fillText(gestureLabel(mode), 16, 24)

        if (!landmarks.length) return

        landmarks.forEach((landmark, index) => {
            if (index !== THUMB_TIP && index !== INDEX_TIP) return
            const point = pointFor(landmark)
            ctx.beginPath()
            ctx.fillStyle = 'rgba(255, 255, 255, 0.92)'
            ctx.arc(point.x, point.y, 4.2, 0, Math.PI * 2)
            ctx.fill()
        })
    }
}
