import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { etthApi } from '../lib/api'
import { Play, Pause, Filter, ShieldAlert } from 'lucide-react'
import type { BehavioralFeature } from '../types/api'

export default function LiveStream() {
  const navigate = useNavigate()
  const [isLive, setIsLive] = useState(true)
  const [flows, setFlows] = useState<BehavioralFeature[]>([])
  const [filterMalicious, setFilterMalicious] = useState(false)

  // Simulate a live stream by polling the search API
  // In a real app, this would be a WebSocket connection
  useEffect(() => {
    if (!isLive) return

    const fetchLatest = async () => {
      try {
        const res = await etthApi.flows.search({
          limit: 15,
          label: filterMalicious ? 'MALICIOUS' : undefined,
        })
        
        // Jitter the results to look like a live stream
        const shuffled = [...res.features].sort(() => 0.5 - Math.random())
        const newEvent = shuffled[0]
        
        if (newEvent) {
          setFlows(prev => {
            const exists = prev.find(f => f.flow_id === newEvent.flow_id)
            if (exists) return prev
            return [newEvent, ...prev].slice(0, 50) // Keep last 50
          })
        }
      } catch (e) {
        console.error(e)
      }
    }

    fetchLatest() // initial
    const interval = setInterval(fetchLatest, 1200)
    return () => clearInterval(interval)
  }, [isLive, filterMalicious])

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
          <p className="text-[11px] text-etth-text/40 mt-0.5 font-mono">
            /var/log/etth/stream.log
          </p>
        </div>
        
        <div className="flex items-center gap-2">
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
            onClick={() => setIsLive(!isLive)}
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
          <div className="col-span-3">Flow ID</div>
          <div className="col-span-1">Label</div>
          <div className="col-span-3">JA3</div>
          <div className="col-span-2">SNI</div>
          <div className="col-span-2 text-right">Bytes</div>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-auto p-1 space-y-[1px]">
          {flows.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-etth-text/30 text-sm">
              <ShieldAlert className="w-8 h-8 mb-2 opacity-20" />
              Waiting for incoming packets...
            </div>
          ) : (
            flows.map((flow, i) => (
              <div 
                key={`${flow.flow_id}-${i}`}
                onClick={() => navigate(`/flows/${flow.flow_id}`)}
                className="grid grid-cols-12 gap-2 px-2 py-1.5 text-[11px] hover:bg-surface-800 cursor-pointer border-l-2 border-transparent hover:border-surface-600 transition-none font-mono"
                style={{
                  animation: 'slideDown 0.1s ease-out',
                }}
              >
                <div className="col-span-1 text-etth-text/30">
                  {new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' })}
                </div>
                <div className="col-span-3 truncate text-etth-text/70">
                  {flow.flow_id}
                </div>
                <div className="col-span-1">
                  {flow.label === 'MALICIOUS' ? (
                    <span className="text-[9px] bg-danger text-white px-1 py-0.5 rounded-sm font-medium">THREAT</span>
                  ) : (
                    <span className="text-[9px] text-etth-text/30 px-1 py-0.5 font-medium">OK</span>
                  )}
                </div>
                <div className="col-span-3 truncate text-etth-text/50">
                  {flow.ja3_hash || '-'}
                </div>
                <div className="col-span-2 truncate text-etth-text/50">
                  {flow.alpn_value || '-'}
                </div>
                <div className="col-span-2 text-right text-info/70">
                  {flow.total_bytes.toLocaleString()}
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
