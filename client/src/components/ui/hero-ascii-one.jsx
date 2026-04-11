export default function HeroAsciiOne({ children }) {
  const host = window.location.hostname || 'localhost'
  const port = window.location.port || (window.location.protocol === 'https:' ? '443' : '80')

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
          <span>HOST: {host.toUpperCase()}</span>
          <i />
          <span>PORT: {port}</span>
        </div>
      </div>

      {children}
    </main>
  )
}
