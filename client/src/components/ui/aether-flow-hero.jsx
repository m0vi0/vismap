import React from 'react'
import { motion } from 'framer-motion'
import { ArrowRight, Zap } from 'lucide-react'

const cn = (...classes) => classes.filter(Boolean).join(' ')
const MotionDiv = motion.div
const MotionH1 = motion.h1
const MotionP = motion.p

function createParticle(x, y, directionX, directionY, size, color) {
  return { x, y, directionX, directionY, size, color }
}

function drawParticle(ctx, particle) {
  ctx.beginPath()
  ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2, false)
  ctx.fillStyle = particle.color
  ctx.fill()
}

function updateParticle(ctx, canvas, mouse, particle) {
  if (particle.x > canvas.width || particle.x < 0) particle.directionX = -particle.directionX
  if (particle.y > canvas.height || particle.y < 0) particle.directionY = -particle.directionY

  if (mouse.x !== null && mouse.y !== null) {
    const dx = mouse.x - particle.x
    const dy = mouse.y - particle.y
    const distance = Math.sqrt(dx * dx + dy * dy) || 1
    if (distance < mouse.radius + particle.size) {
      const forceDirectionX = dx / distance
      const forceDirectionY = dy / distance
      const force = (mouse.radius - distance) / mouse.radius
      particle.x -= forceDirectionX * force * 4.5
      particle.y -= forceDirectionY * force * 4.5
    }
  }

  particle.x += particle.directionX
  particle.y += particle.directionY
  drawParticle(ctx, particle)
}

export default function AetherFlowHero({
  badge = 'Host Packet Flow',
  title = 'VISMAP',
  description = 'Live network traffic rendered as a spatial packet graph. Nodes grow with traffic volume and packets travel directly along active links.',
  actionLabel = 'Capture from host',
  className,
  children,
}) {
  const canvasRef = React.useRef(null)

  React.useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined

    const ctx = canvas.getContext('2d')
    let animationFrameId
    let particles = []
    const mouse = { x: null, y: null, radius: 190 }

    function init() {
      particles = []
      const numberOfParticles = Math.min((canvas.height * canvas.width) / 10500, 150)
      for (let i = 0; i < numberOfParticles; i += 1) {
        const size = Math.random() * 1.8 + 1
        const x = Math.random() * (canvas.width - size * 4) + size * 2
        const y = Math.random() * (canvas.height - size * 4) + size * 2
        const directionX = Math.random() * 0.34 - 0.17
        const directionY = Math.random() * 0.34 - 0.17
        const color = i % 4 === 0 ? 'rgba(255, 200, 87, 0.82)' : 'rgba(92, 235, 255, 0.82)'
        particles.push(createParticle(x, y, directionX, directionY, size, color))
      }
    }

    const resizeCanvas = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
      init()
    }

    const connect = () => {
      for (let a = 0; a < particles.length; a += 1) {
        for (let b = a + 1; b < particles.length; b += 1) {
          const dx = particles[a].x - particles[b].x
          const dy = particles[a].y - particles[b].y
          const distance = dx * dx + dy * dy
          const limit = (canvas.width / 8) * (canvas.height / 8)

          if (distance < limit) {
            const opacityValue = Math.max(0, 1 - distance / 19000)
            const mouseDx = particles[a].x - mouse.x
            const mouseDy = particles[a].y - mouse.y
            const mouseDistance = Math.sqrt(mouseDx * mouseDx + mouseDy * mouseDy)
            ctx.strokeStyle = mouse.x && mouseDistance < mouse.radius
              ? `rgba(247, 251, 250, ${opacityValue})`
              : `rgba(92, 235, 255, ${opacityValue * 0.72})`
            ctx.lineWidth = 1
            ctx.beginPath()
            ctx.moveTo(particles[a].x, particles[a].y)
            ctx.lineTo(particles[b].x, particles[b].y)
            ctx.stroke()
          }
        }
      }
    }

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate)
      ctx.fillStyle = '#07110f'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      particles.forEach((particle) => updateParticle(ctx, canvas, mouse, particle))
      connect()
    }

    const handleMouseMove = (event) => {
      mouse.x = event.clientX
      mouse.y = event.clientY
    }

    const handleMouseOut = () => {
      mouse.x = null
      mouse.y = null
    }

    window.addEventListener('resize', resizeCanvas)
    window.addEventListener('mousemove', handleMouseMove)
    window.addEventListener('mouseout', handleMouseOut)
    resizeCanvas()
    animate()

    return () => {
      window.removeEventListener('resize', resizeCanvas)
      window.removeEventListener('mousemove', handleMouseMove)
      window.removeEventListener('mouseout', handleMouseOut)
      cancelAnimationFrame(animationFrameId)
    }
  }, [])

  const fadeUpVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i) => ({
      opacity: 1,
      y: 0,
      transition: {
        delay: i * 0.12 + 0.18,
        duration: 0.64,
        ease: 'easeInOut',
      },
    }),
  }

  return (
    <div className={cn('aetherFlowHero', className)}>
      <canvas ref={canvasRef} className="aetherCanvas" aria-hidden="true" />
      <div className="aetherShade" />

      <div className="aetherIntro">
        <MotionDiv
          custom={0}
          variants={fadeUpVariants}
          initial="hidden"
          animate="visible"
          className="aetherBadge"
        >
          <Zap aria-hidden="true" />
          <span>{badge}</span>
        </MotionDiv>

        <MotionH1 custom={1} variants={fadeUpVariants} initial="hidden" animate="visible">
          {title}
        </MotionH1>

        <MotionP custom={2} variants={fadeUpVariants} initial="hidden" animate="visible">
          {description}
        </MotionP>

        <MotionDiv custom={3} variants={fadeUpVariants} initial="hidden" animate="visible">
          <span className="aetherAction">
            {actionLabel}
            <ArrowRight aria-hidden="true" />
          </span>
        </MotionDiv>
      </div>

      {children}
    </div>
  )
}
