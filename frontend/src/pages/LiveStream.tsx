import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play, Pause, Filter, ShieldAlert, Wifi, WifiOff, Gauge } from 'lucide-react'
import { useWebSocket } from '../lib/useWebSocket'

export default function LiveStream() {
  const navigate = useNavigate()
  const [filterMalicious, setFilterMalicious] = useState(false)
  const {
    isConnected,
    streamState,
    speed,
    events,
    pauseReplay,
    resumeReplay,
    setSpeed,
    startReplay
  } = useWebSocket(100)

  const isLive = streamState === 'RUNNING'

  const filteredEvents = filterMalicious
    ? events.filter(e => e.prediction === 'MALICIOUS' || e.label_ground_truth?.includes('MALICIOUS'))
    : events

  const togglePlayPause = () => {
    if (isLive) {
      pauseReplay()
    } else if (streamState === 'PAUSED') {
      resumeReplay()
    } else {
      startReplay(speed, filterMalicious)
    }
  }

  const handleSpeedChange = (newSpeed: number) => {
    setSpeed(newSpeed)
  }

  return (
    <div className="p-4 lg:p-6 h-[calc(100vh-3rem)] flex flex-col max-w-[1600px] mx-auto">
      <div className="flex items-center justify-between mb-4 shrink-0">
        <div>
          <h1 className="text-lg font-semibold text-etth-text flex items-center gap-2">
            Live Traffic Stream
            {isLive && (
              <span className="relative flex h-1.5 w-1.5 ml-1">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-danger opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-danger" />
              </span>
            )}
          </h1>
          <div className="flex items-center gap-3 mt-0.5">
            <p className="text-[11px] text-etth-text/40 font-mono">
              ws://localhost:8000/ws/live-stream
            </p>
            <span className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded ${
              isConnected ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'
            }`}>
              {isConnected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
              {isConnected ? 'LIVE WS CONNECTED' : 'RECONNECTING...'}
            </span>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          {/* Speed selector */}
          <div className="flex items-center bg-surface-800 border border-surface-700 rounded-sm p-0.5">
            <Gauge className="w-3.5 h-3.5 ml-1.5 mr-1 text-etth-text/40" />
            {[0.5, 1, 2, 5].map((s) => (
              <button
                key={s}
                onClick={() => handleSpeedChange(s)}
                className={`px-2 py-0.5 text-[10px] font-mono rounded-xs transition-none ${
                  speed === s ? 'bg-accent text-white font-medium' : 'text-etth-text/50 hover:text-etth-text'
                }`}
              >
                {s}x
              </button>
            ))}
          </div>

          <button
            onClick={() => setFilterMalicious(!filterMalicious)}
            className={`px-3 py-1.5 text-xs font-medium rounded-sm flex items-center gap-1.5 border transition-none ${
              filterMalicious 
                ? 'bg-danger/10 text-danger border-danger/20' 
                : 'bg-surface-800 text-etth-text/60 border-surface-700 hover:bg-surface-700'
            }`}
          >
            <Filter className="w-3.5 h-3.5" />
            Threats Only
          </button>
          
          <button
            onClick={togglePlayPause}
            className={`px-3 py-1.5 text-xs font-medium rounded-sm flex items-center gap-1.5 transition-none ${
              isLive 
                ? 'bg-surface-700 text-etth-text hover:bg-surface-600' 
                : 'bg-accent text-white hover:bg-accent/90'
            }`}
          >
            {isLive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {isLive ? 'Pause Stream' : 'Resume'}
          </button>
        </div>
      </div>

      <div className="flex-1 bg-surface-900 border border-surface-700 rounded-sm flex flex-col min-h-0">
        {/* Table Header */}
        <div className="grid grid-cols-12 gap-2 p-2 border-b border-surface-700 bg-surface-800 text-[10px] font-medium text-etth-text/40 uppercase tracking-wider shrink-0">
          <div className="col-span-1">Time</div>
          <div className="col-span-3">Flow ID / Dataset</div>
          <div className="col-span-2">Prediction & Score</div>
          <div className="col-span-3">JA3 Hash</div>
          <div className="col-span-1">SNI / ALPN</div>
          <div className="col-span-2 text-right">Bytes / Pkts</div>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-auto p-1 space-y-[1px]">
          {filteredEvents.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-etth-text/30 text-sm">
              <ShieldAlert className="w-8 h-8 mb-2 opacity-20" />
              Waiting for incoming WebSocket packets...
            </div>
          ) : (
            filteredEvents.map((event, i) => (
              <div 
                key={`${event.event_id}-${i}`}
                onClick={() => navigate(`/flows/${event.flow_id}`)}
                className="grid grid-cols-12 gap-2 px-2 py-1.5 text-[11px] hover:bg-surface-800 cursor-pointer border-l-2 border-transparent hover:border-surface-600 transition-none font-mono"
                style={{
                  animation: 'slideDown 0.1s ease-out',
                }}
              >
                <div className="col-span-1 text-etth-text/30 truncate">
                  {event.timestamp ? new Date(event.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' }) : '-'}
                </div>
                <div className="col-span-3 truncate text-etth-text/70 flex items-center gap-1.5">
                  <span className="truncate">{event.flow_id}</span>
                  {event.dataset_id && (
                    <span className="text-[9px] bg-surface-700 text-etth-text/40 px-1 py-0.2 rounded shrink-0 font-sans">
                      {event.dataset_id}
                    </span>
                  )}
                </div>
                <div className="col-span-2 flex items-center gap-1.5">
                  {event.prediction === 'MALICIOUS' ? (
                    <span className="text-[9px] bg-danger text-white px-1.5 py-0.5 rounded-sm font-medium">THREAT</span>
                  ) : (
                    <span className="text-[9px] bg-surface-700 text-etth-text/50 px-1.5 py-0.5 rounded-sm font-medium">BENIGN</span>
                  )}
                  <span className={`text-[10px] ${event.threat_score >= 0.5 ? 'text-danger font-semibold' : 'text-etth-text/40'}`}>
                    {(event.threat_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="col-span-3 truncate text-etth-text/50">
                  {event.ja3_hash || '-'}
                </div>
                <div className="col-span-1 truncate text-etth-text/50">
                  {event.alpn_value || (event.sni_present ? 'SNI' : '-')}
                </div>
                <div className="col-span-2 text-right text-info/70">
                  {event.total_bytes ? event.total_bytes.toLocaleString() : 0} B
                </div>
              </div>
            ))
          )}
        </div>
      </div>
      
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes slideDown {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}} />
    </div>
  )
}
