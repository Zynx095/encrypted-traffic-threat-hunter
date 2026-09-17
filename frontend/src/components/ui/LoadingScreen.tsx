import { useEffect, useState } from 'react'
import { ShihTzuMark } from './ShihTzuMark'

export interface LoadingScreenProps {
  minimumLoadTimeMs?: number
  onFinished?: () => void
}

export function LoadingScreen({ minimumLoadTimeMs = 1200, onFinished }: LoadingScreenProps) {
  const [fading, setFading] = useState(false)
  const [hidden, setHidden] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => {
      setFading(true)
      const hideTimer = setTimeout(() => {
        setHidden(true)
        if (onFinished) onFinished()
      }, 500) // matches CSS transition duration
      return () => clearTimeout(hideTimer)
    }, minimumLoadTimeMs)

    return () => clearTimeout(timer)
  }, [minimumLoadTimeMs, onFinished])

  if (hidden) return null

  return (
    <div
      className={`loading-screen-overlay ${fading ? 'opacity-0 pointer-events-none' : 'opacity-100'}`}
      aria-label="Loading application"
    >
      {/* Green Matrix Network Packet Rain Background */}
      <div className="matrix-container">
        <div className="matrix-pattern">
          {Array.from({ length: 20 }).map((_, i) => (
            <div key={i} className="matrix-column" />
          ))}
        </div>
      </div>

      <div className="relative z-10 flex flex-col items-center">
        <div className="flex items-center gap-2.5 mb-6">
          <ShihTzuMark size={36} className="text-accent" />
          <div className="text-left font-sans">
            <div className="text-sm font-semibold text-etth-text tracking-widest uppercase">ETTH</div>
            <div className="text-[10px] font-mono text-etth-text/40">Encrypted Traffic Threat Hunter</div>
          </div>
        </div>

        <div className="loadingspinner">
          <div id="square1"></div>
          <div id="square2"></div>
          <div id="square3"></div>
          <div id="square4"></div>
          <div id="square5"></div>
        </div>
        <div className="text-center font-mono text-xs uppercase tracking-widest text-etth-text/60 mt-2">
          INITIALIZING ETTH PIPELINE...
        </div>
      </div>
    </div>
  )
}


