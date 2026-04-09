import { useMemo } from 'react'

export default function HeroAsciiOne({ children }) {
  const bars = useMemo(
    () => Array.from({ length: 8 }, (_, index) => 5 + ((index * 7) % 13)),
    [],
  )

  return (
    <main className="asciiHero">
      <div className="asciiStars" aria-hidden="true" />
      <div className="asciiNoise" aria-hidden="true" />

      <div className="asciiHeader">
        <div className="asciiBrand">
          <div className="asciiLogo">VISMAP</div>
          <div className="asciiDivider" />
          <span>EST. 2026</span>
        </div>

        <div className="asciiCoords">
          <span>LAT: LOCALHOST</span>
          <i />
          <span>PORT: 8080</span>
        </div>
      </div>

      <div className="corner cornerTopLeft" />
      <div className="corner cornerTopRight" />
      <div className="corner cornerBottomLeft" />
      <div className="corner cornerBottomRight" />

      {children}

      <div className="asciiFooter">
        <div>
          <span>SYSTEM.ACTIVE</span>
          <div className="asciiBars" aria-hidden="true">
            {bars.map((height, index) => (
              <i key={index} style={{ height }} />
            ))}
          </div>
          <span>V1.0.0</span>
        </div>

        <div>
          <span>GRAPH.STATIONARY</span>
          <div className="asciiPulse" aria-hidden="true">
            <i />
            <i />
            <i />
          </div>
          <span>PACKETS: LIVE</span>
        </div>
      </div>
    </main>
  )
}
