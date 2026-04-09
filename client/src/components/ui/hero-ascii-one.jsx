export default function HeroAsciiOne({ children }) {
  return (
    <main className="asciiHero">
      <div className="asciiStars" aria-hidden="true" />
      <div className="asciiNoise" aria-hidden="true" />

      <div className="asciiHeader">
        <div className="asciiBrand">
          <div className="asciiLogo">pacmap</div>
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
    </main>
  )
}
