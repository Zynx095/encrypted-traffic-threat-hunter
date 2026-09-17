import React, { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useWebSocket } from '../lib/useWebSocket'
import type { ModelTrack, StreamState, ETTHStreamEvent } from '../types/api'
import { Badge } from '../components/ui/Badge'
import { 
  Play, Pause, Square, ShieldAlert, Wifi, WifiOff, Download, ExternalLink, X, Check, Copy
} from 'lucide-react'

export default function LiveStream() {
  const location = useLocation()
  const navigate = useNavigate()
  const { target_id, target_name, initialMode } = location.state || {}

  const [selectedMode, setSelectedMode] = useState<'REPLAY' | 'LIVE'>(initialMode || 'REPLAY')
  const [filterMalicious, setFilterMalicious] = useState(false)
  const [selectedEvent, setSelectedEvent] = useState<ETTHStreamEvent | null>(null)
  const [showApprovedDetails, setShowApprovedDetails] = useState(false)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const {
    isConnected,
    streamState,
    speed,
    track,
    events,
    telemetry,
    interfaces,
    selectedInterface,
    captureStatus,
    pauseReplay,
    resumeReplay,
    stopReplay,
    stopLive,
    setSpeed,
    setTrack,
    selectInterface,
    startReplay,
    startLive
  } = useWebSocket(100)

  const handleStartReplay = () => startReplay(speed, filterMalicious, track, target_id)
  const handleStartLive = () => startLive(selectedInterface, track, target_id)
  const handlePause = () => pauseReplay()
  const handleResume = () => resumeReplay()
  const handleStop = () => {
    if (selectedMode === 'LIVE') stopLive()
    else stopReplay()
  }

  const handleSpeedChange = (newSpeed: number) => setSpeed(newSpeed)
  const handleTrackChange = (newTrack: ModelTrack) => setTrack(newTrack)

  const handleCopy = (text: string, field: string) => {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const tracks: { id: ModelTrack; label: string }[] = [
    { id: 'A_FLOW', label: 'Track A (Flow)' },
    { id: 'B_JA3', label: 'Track B (JA3)' },
    { id: 'C_JA4', label: 'Track C (JA4)' },
    { id: 'D_JA3_FLOW', label: 'Track D (JA3+Flow)' },
    { id: 'E_JA4_FLOW', label: 'Track E (JA4+Flow)' },
  ]

  const processedCount = telemetry?.processed_events ?? 0
  const totalCount = telemetry?.total_events ?? 0
  const progressPct = telemetry?.progress_percentage ?? (totalCount > 0 ? (processedCount / totalCount) * 100 : 0)
  const eps = telemetry?.events_per_second ?? 0
  const maliciousCount = telemetry?.malicious_events ?? 0
  const benignCount = telemetry?.benign_events ?? 0
  const skippedCount = telemetry?.skipped_events ?? 0
  
  const totalVolume = events.reduce((sum, e) => sum + (e.flow?.total_bytes || 0), 0)
  const mbVolume = (totalVolume / (1024 * 1024)).toFixed(2)

  // Filter flagged events
  const flaggedEvents = events.filter(
    e => e.detection?.prediction === 'MALICIOUS' || (e.detection?.threat_score && e.detection.threat_score >= 0.5)
  )

  return (
    <div className="flex flex-col w-full h-[calc(100vh-3.5rem)] text-etth-text select-none pb-8 overflow-y-auto bg-surface-900 p-4">
      {/* IN-PAGE WORKSPACE BANNER & TARGET META */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 bg-surface-800 px-4 py-3 mb-4 rounded-sm border border-surface-700/50">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-1.5 font-mono text-xs text-etth-text/40">
            <span className="text-accent font-medium">ETTH</span>
            <span>/</span>
            <span className="text-etth-text">Live Monitor</span>
            {target_name && (
              <>
                <span>/</span>
                <span className="text-etth-text/70">{target_name}</span>
              </>
            )}
          </div>
          <div className="h-4 w-px bg-surface-700 hidden sm:block"></div>
          <div className="flex items-center gap-2">
            <span className="text-lg font-semibold text-etth-text">{target_name || 'Global Stream'}</span>
            <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface-700/50 text-etth-text/80 font-mono text-xs font-medium border border-surface-600/30">
              <span className={`w-1.5 h-1.5 rounded-full ${streamState === 'PLAYING' ? 'bg-success animate-pulse' : streamState === 'PAUSED' ? 'bg-warning' : 'bg-surface-500'}`}></span>
              {streamState}
            </span>
            <span className={`flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-mono border ${isConnected ? 'bg-success/10 text-success border-success/20' : 'bg-danger/10 text-danger border-danger/20'}`}>
              {isConnected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
              {isConnected ? 'WS CONNECTED' : 'DISCONNECTED'}
            </span>
          </div>
        </div>

        {/* Restrained Tactile Security Workstation Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center bg-surface-900 p-0.5 rounded-sm border border-surface-700/50">
            <button 
              onClick={() => setSelectedMode('REPLAY')}
              className={`px-3 py-1 rounded-sm font-mono text-xs transition-none ${selectedMode === 'REPLAY' ? 'bg-surface-700 text-etth-text font-medium' : 'text-etth-text/50 hover:text-etth-text'}`}
            >
              Replay
            </button>
            <button 
              onClick={() => setSelectedMode('LIVE')}
              className={`px-3 py-1 rounded-sm font-mono text-xs transition-none ${selectedMode === 'LIVE' ? 'bg-surface-700 text-etth-text font-medium' : 'text-etth-text/50 hover:text-etth-text'}`}
            >
              Live
            </button>
          </div>

          {selectedMode === 'LIVE' ? (
            <div className="flex items-center gap-1 px-2 py-1 rounded-sm bg-surface-900 border border-surface-700/50 font-mono text-xs text-etth-text/70">
              <span className="text-etth-text/40">NIC:</span>
              <select
                value={selectedInterface}
                onChange={(e) => selectInterface(e.target.value)}
                disabled={captureStatus === 'CAPTURE_UNAVAILABLE'}
                className="bg-transparent text-etth-text font-medium focus:outline-none cursor-pointer max-w-[150px] truncate"
              >
                {interfaces.length === 0 ? (
                  <option value="">No Interfaces</option>
                ) : (
                  interfaces.map((iface) => (
                    <option key={iface.id} value={iface.id}>{iface.name}</option>
                  ))
                )}
              </select>
            </div>
          ) : (
            <div className="flex items-center bg-surface-900 border border-surface-700/50 rounded-sm p-0.5">
              {[0.5, 1, 2, 5].map((s) => (
                <button
                  key={s}
                  onClick={() => handleSpeedChange(s)}
                  className={`px-2 py-0.5 text-[10px] font-mono rounded-sm transition-none ${
                    speed === s ? 'bg-surface-700 text-etth-text font-medium' : 'text-etth-text/50 hover:text-etth-text'
                  }`}
                >
                  {s}x
                </button>
              ))}
            </div>
          )}

          <div className="flex items-center gap-1 px-2 py-1 rounded-sm bg-surface-900 border border-surface-700/50 font-mono text-xs text-etth-text/70">
            <span className="text-etth-text/40">Track:</span>
            <select
              value={track}
              onChange={(e) => handleTrackChange(e.target.value as ModelTrack)}
              className="bg-transparent text-etth-text font-medium focus:outline-none cursor-pointer"
            >
              {tracks.map((t) => (
                <option key={t.id} value={t.id}>{t.label}</option>
              ))}
            </select>
          </div>

          <div className="h-5 w-px bg-surface-700 mx-1"></div>

          {streamState === 'PLAYING' ? (
            <button onClick={handlePause} className="flex items-center gap-1 px-3 py-1 rounded-sm bg-surface-700 hover:bg-surface-600 text-etth-text font-mono text-xs border border-surface-600/50">
              <Pause className="w-3.5 h-3.5 text-etth-text/70" />
              <span>Pause</span>
            </button>
          ) : streamState === 'PAUSED' ? (
            <button onClick={handleResume} className="flex items-center gap-1 px-3 py-1 rounded-sm bg-surface-700 hover:bg-surface-600 text-etth-text font-mono text-xs border border-surface-600/50">
              <Play className="w-3.5 h-3.5 text-etth-text/70" />
              <span>Resume</span>
            </button>
          ) : (
            <button 
              onClick={selectedMode === 'LIVE' ? handleStartLive : handleStartReplay} 
              disabled={selectedMode === 'LIVE' && captureStatus === 'CAPTURE_UNAVAILABLE'}
              className="flex items-center gap-1 px-3 py-1 rounded-sm bg-surface-700 hover:bg-surface-600 text-etth-text font-mono text-xs border border-surface-600/50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className="w-3.5 h-3.5 text-etth-text/70" />
              <span>Start</span>
            </button>
          )}

          {(streamState === 'PLAYING' || streamState === 'PAUSED') && (
            <button onClick={handleStop} className="flex items-center gap-1 px-3 py-1 rounded-sm bg-danger/10 hover:bg-danger/20 text-danger font-mono text-xs border border-danger/20">
              <Square className="w-3.5 h-3.5" />
              <span>Stop</span>
            </button>
          )}

          <button className="flex items-center gap-1 px-3 py-1 rounded-sm bg-surface-900 hover:bg-surface-700 text-etth-text/70 hover:text-etth-text font-mono text-xs border border-surface-700/50 ml-1">
            <Download className="w-3.5 h-3.5" />
            <span>Export PCAP</span>
          </button>
        </div>
      </div>

      {/* SESSION TELEMETRY STRIP (Dense unified bar with vertical hairline dividers) */}
      <section className="bg-surface-800 px-4 py-3 rounded-sm border border-surface-700/50 mb-4 flex flex-wrap items-center justify-between gap-y-3">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-lg font-semibold text-etth-text">{processedCount.toLocaleString()}</span>
            <span className="font-mono text-xs text-etth-text/40 uppercase">flows observed</span>
          </div>
          <div className="h-5 w-px bg-surface-700"></div>
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-sm bg-accent/10 text-accent font-mono text-xs font-semibold border border-accent/20">
            <span className="w-1.5 h-1.5 rounded-full bg-accent"></span>
            <span>{maliciousCount.toLocaleString()} flagged</span>
          </div>
          <div className="h-5 w-px bg-surface-700"></div>
          <div className="flex items-baseline gap-2 text-success">
            <span className="font-mono text-sm font-semibold">{benignCount.toLocaleString()}</span>
            <span className="font-mono text-xs opacity-80 uppercase">approved</span>
          </div>
          <div className="h-5 w-px bg-surface-700"></div>
          <div className="flex items-baseline gap-2 text-etth-text/40">
            <span className="font-mono text-sm font-medium">{skippedCount.toLocaleString()}</span>
            <span className="font-mono text-xs uppercase">skipped</span>
          </div>
        </div>
        <div className="flex items-center gap-4 flex-wrap font-mono text-xs">
          <div className="flex items-center gap-1.5">
            <span className="text-etth-text/40">Throughput:</span>
            <span className="text-etth-text font-semibold">{eps.toFixed(1)} ev/s</span>
          </div>
          <div className="h-5 w-px bg-surface-700"></div>
          <div className="flex items-center gap-1.5">
            <span className="text-etth-text/40">Pipeline Latency:</span>
            <span className="text-etth-text/70 font-medium">{(telemetry?.processing_duration_ms || 0).toFixed(1)} ms</span>
          </div>
          <div className="h-5 w-px bg-surface-700"></div>
          <div className="flex items-center gap-1.5">
            <span className="text-etth-text/40">Model Inference:</span>
            <span className="text-info font-medium">{(telemetry?.inference_duration_ms || 0).toFixed(1)} ms</span>
          </div>
        </div>
        {totalCount > 0 && (
          <div className="w-full bg-surface-900 h-0.5 mt-2 overflow-hidden rounded-full">
            <div
              className="bg-accent h-full transition-all duration-200"
              style={{ width: `${Math.min(100, Math.max(0, progressPct))}%` }}
            />
          </div>
        )}
      </section>

      {/* MAIN OPERATIONAL WORKSPACE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start flex-1 min-h-0">
        
        {/* LEFT PANE: FLAGGED FLOWS & AGGREGATE PANEL (62% ~ cols-7 or 8) */}
        <div className={`flex flex-col gap-4 min-h-0 ${selectedEvent ? 'lg:col-span-7 xl:col-span-8' : 'lg:col-span-12'}`}>
          
          {/* 1. FLAGGED FLOWS SECTION */}
          <div className="bg-surface-800 rounded-sm border border-surface-700/50 flex flex-col min-h-0 max-h-[60vh]">
            <div className="h-10 px-4 bg-surface-900/50 border-b border-surface-700/50 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-accent"></span>
                <span className="text-xs uppercase text-etth-text tracking-wider font-semibold">Flagged Flows ({flaggedEvents.length})</span>
                <span className="text-etth-text/40 font-mono text-xs">· Priority Queue</span>
              </div>
              <div className="flex items-center gap-1 bg-surface-900 p-0.5 rounded-sm border border-surface-700/50">
                <button className="px-2 py-0.5 rounded-sm bg-surface-700 text-etth-text font-mono text-xs font-medium">All Flagged</button>
                <button className="px-2 py-0.5 rounded-sm text-etth-text/50 hover:text-etth-text font-mono text-xs">High Confidence</button>
              </div>
            </div>
            
            <div className="overflow-auto flex-1">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-surface-900/90 backdrop-blur border-b border-surface-700/50">
                  <tr className="h-8 font-mono text-[10px] uppercase text-etth-text/40 tracking-wider">
                    <th className="px-3 font-medium w-24">Severity</th>
                    <th className="px-3 font-medium">Flow ID</th>
                    <th className="px-3 font-medium">Target</th>
                    <th className="px-3 font-medium">Attribution</th>
                    <th className="px-3 font-medium text-right">Score</th>
                    <th className="px-3 font-medium">Evidence</th>
                    <th className="px-3 font-medium text-right">Bytes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-700/30 text-xs">
                  {flaggedEvents.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="text-center py-12">
                        <ShieldAlert className="w-8 h-8 text-etth-text/20 mx-auto mb-2" />
                        <div className="text-etth-text/60 font-medium">No Flagged Flows</div>
                        <div className="text-etth-text/40 text-[11px] mt-1">Monitoring stream for malicious patterns...</div>
                      </td>
                    </tr>
                  ) : (
                    flaggedEvents.map((event) => {
                      const isSelected = selectedEvent?.event_id === event.event_id
                      const score = event.detection?.threat_score || 0
                      const severity = score > 0.85 ? 'HIGH' : score > 0.65 ? 'MED' : 'LOW'
                      const severityColor = severity === 'HIGH' ? 'text-accent' : severity === 'MED' ? 'text-warning' : 'text-etth-text/50'
                      
                      return (
                        <tr 
                          key={event.event_id}
                          onClick={() => setSelectedEvent(event)}
                          className={`h-9 cursor-pointer transition-colors relative ${
                            isSelected ? 'bg-surface-700/50 text-etth-text' : 'bg-surface-800 text-etth-text/70 hover:bg-surface-700/30'
                          }`}
                        >
                          <td className={`px-3 font-mono text-[10px] font-medium ${severityColor} flex items-center gap-1.5 h-9`}>
                            {isSelected && <span className="w-1 h-5 bg-accent absolute left-0 top-2 rounded-r"></span>}
                            <span>● {severity}</span>
                          </td>
                          <td className="px-3 font-mono text-[11px] font-medium text-info">{event.flow?.flow_id}</td>
                          <td className="px-3 text-etth-text/80 truncate max-w-[120px]">{event.target_id || event.attribution?.target_id || 'Unknown'}</td>
                          <td className="px-3">
                            <span className="px-1.5 py-0.5 rounded-sm bg-surface-900 border border-surface-700 text-etth-text/60 font-mono text-[10px]">
                              {event.attribution?.status || 'UNVERIFIED'}
                            </span>
                          </td>
                          <td className={`px-3 font-mono text-[11px] text-right font-semibold ${severityColor}`}>
                            {(score * 100).toFixed(1)}%
                          </td>
                          <td className="px-3 text-etth-text/50 truncate max-w-[180px] text-[11px]">
                            {event.detection?.evidence?.[0] || event.tls?.ja3_hash || '—'}
                          </td>
                          <td className="px-3 font-mono text-[11px] text-right text-etth-text/50">
                            {(event.flow?.total_bytes || 0).toLocaleString()} B
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* 2. APPROVED TRAFFIC ACCORDION / DENSE AGGREGATE PANEL */}
          <div className="bg-surface-800 rounded-sm border border-surface-700/50 flex flex-col shrink-0">
            <button 
              onClick={() => setShowApprovedDetails(!showApprovedDetails)}
              className="w-full h-10 px-4 bg-surface-900/50 flex items-center justify-between text-left hover:bg-surface-700/30 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-success"></span>
                <span className="text-xs uppercase text-etth-text tracking-wider font-semibold">Approved Traffic</span>
                <span className="font-mono text-xs text-etth-text/40">({benignCount.toLocaleString()} flows · {mbVolume} MB aggregated)</span>
              </div>
              <div className="flex items-center gap-1 font-mono text-xs text-info font-medium">
                <span>{showApprovedDetails ? 'Hide' : 'View'} aggregate breakdown</span>
                <span className={`material-symbols-outlined text-base transition-transform ${showApprovedDetails ? '' : '-rotate-90'}`}></span>
              </div>
            </button>

            {showApprovedDetails && (
              <div className="p-4 flex flex-col gap-4 border-t border-surface-700/50">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-sm bg-surface-900 border border-surface-700/50 flex flex-col gap-1">
                    <span className="text-etth-text/40 uppercase text-[10px]">Total Flows Processed</span>
                    <span className="text-sm font-semibold text-etth-text">{processedCount.toLocaleString()}</span>
                  </div>
                  <div className="p-3 rounded-sm bg-surface-900 border border-surface-700/50 flex flex-col gap-1">
                    <span className="text-etth-text/40 uppercase text-[10px]">Total Volume</span>
                    <span className="text-sm font-semibold text-etth-text">{mbVolume} MB</span>
                  </div>
                  <div className="p-3 rounded-sm bg-surface-900 border border-surface-700/50 flex flex-col gap-1">
                    <span className="text-etth-text/40 uppercase text-[10px]">Processing Rate</span>
                    <span className="text-sm font-semibold text-etth-text">{eps.toFixed(1)} ev/s</span>
                  </div>
                  <div className="p-3 rounded-sm bg-surface-900 border border-surface-700/50 flex flex-col gap-1">
                    <span className="text-etth-text/40 uppercase text-[10px]">Verified Benign Ratio</span>
                    <span className="text-sm font-semibold text-success">
                      {processedCount > 0 ? ((benignCount / processedCount) * 100).toFixed(2) : '0.00'}%
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="flex flex-col gap-4 p-3 rounded-sm bg-surface-900 border border-surface-700/50">
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between font-mono text-[10px] uppercase text-etth-text/40">
                        <span>Traffic Disposition</span>
                      </div>
                      <div className="h-2 w-full bg-surface-800 rounded-full overflow-hidden flex">
                        <div className="h-full bg-success" style={{ width: `${(benignCount/Math.max(1, processedCount))*100}%` }}></div>
                        <div className="h-full bg-warning" style={{ width: `${(skippedCount/Math.max(1, processedCount))*100}%` }}></div>
                        <div className="h-full bg-accent" style={{ width: `${(maliciousCount/Math.max(1, processedCount))*100}%` }}></div>
                      </div>
                      <div className="flex items-center justify-between font-mono text-[10px] text-etth-text/50 pt-1">
                        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-success"></span>Approved</span>
                        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-warning"></span>Skipped</span>
                        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-accent"></span>Flagged</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex flex-col justify-between p-3 rounded-sm bg-surface-900 border border-surface-700/50">
                    <div className="flex items-center justify-between font-mono text-[10px] uppercase text-etth-text/40 mb-2">
                      <span>Pipeline Audit</span>
                    </div>
                    <div className="text-xs text-etth-text/60">
                      Full behavioral & TLS feature validation active. No TLS decryption performed.
                      <br/>
                      <br/>
                      Approved traffic is aggregated in real-time. Individual benign events are discarded from active UI rendering to optimize memory.
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT PANE: FLOW INSPECTION DRAWER (Contextual detail for selected event) */}
        {selectedEvent && (
          <div className="lg:col-span-5 xl:col-span-4 bg-surface-800 rounded-sm border border-surface-700/50 flex flex-col sticky top-0 max-h-[calc(100vh-140px)] overflow-hidden">
            {/* Drawer Header Bar */}
            <div className="h-10 px-4 bg-surface-900/50 border-b border-surface-700/50 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-xs uppercase text-etth-text tracking-wider font-semibold truncate">Flow Inspection</span>
                <span className="font-mono text-[10px] text-info px-1.5 py-0.5 rounded-sm bg-surface-900 border border-surface-700/50 truncate max-w-[120px]">
                  {selectedEvent.flow?.flow_id}
                </span>
              </div>
              <div className="flex items-center gap-1">
                <button 
                  onClick={() => navigate(`/flows/${selectedEvent.flow?.flow_id}`, { state: { liveEvent: selectedEvent } })}
                  className="flex items-center gap-1 px-2 py-0.5 rounded-sm bg-surface-900 hover:bg-surface-700 border border-surface-700/50 text-etth-text/70 hover:text-etth-text font-mono text-[10px]"
                >
                  <ExternalLink className="w-3 h-3" />
                  <span>Full</span>
                </button>
                <button 
                  onClick={() => setSelectedEvent(null)}
                  className="p-1 rounded-sm text-etth-text/50 hover:text-etth-text hover:bg-surface-700"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Drawer Content Stream */}
            <div className="p-4 flex flex-col gap-4 overflow-y-auto">
              
              {/* SECTION 1: FLOW IDENTIFIERS */}
              <section className="flex flex-col gap-2 pb-2 border-b border-surface-700/50">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] uppercase text-etth-text/40">Flow Identifiers</span>
                  <span className="font-mono text-[10px] text-etth-text/40">5-TUPLE</span>
                </div>
                <div className="flex flex-col gap-1.5 font-mono text-[11px]">
                  <div className="flex items-center justify-between text-etth-text/50">
                    <span>Flow ID:</span>
                    <span className="text-etth-text selection:bg-info selection:text-white truncate max-w-[200px]">{selectedEvent.flow?.flow_id}</span>
                  </div>
                  <div className="flex items-center justify-between text-etth-text/50">
                    <span>Target:</span>
                    <span className="text-etth-text">{selectedEvent.target_id || selectedEvent.attribution?.target_id || 'Unknown'}</span>
                  </div>
                  <div className="flex items-center justify-between text-etth-text/50">
                    <span>Session:</span>
                    <span className="text-etth-text">{selectedEvent.session_id}</span>
                  </div>
                  <div className="mt-1 p-2 rounded-sm bg-surface-900 border border-surface-700/50 flex items-center justify-between font-mono text-[10px]">
                    <span className="text-etth-text/70 font-medium">{selectedEvent.flow?.forward_endpoint || 'Any'}</span>
                    <span className="text-info font-bold">→</span>
                    <span className="text-etth-text font-semibold">{selectedEvent.flow?.reverse_endpoint || 'Any'}</span>
                    <span className="px-1 py-0.5 rounded-sm bg-surface-800 text-etth-text/40 border border-surface-700 text-[9px]">{selectedEvent.flow?.protocol || 'ANY'}</span>
                  </div>
                </div>
              </section>

              {/* SECTION 2: ATTRIBUTION */}
              <section className="flex flex-col gap-2 pb-2 border-b border-surface-700/50">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] uppercase text-etth-text/40">Attribution & Confidence</span>
                  <span className={`px-1.5 py-0.5 rounded-sm font-mono text-[10px] font-semibold border ${
                    selectedEvent.attribution?.status === 'ATTRIBUTED' ? 'bg-info/10 text-info border-info/20' : 
                    selectedEvent.attribution?.status === 'PROBABLE' ? 'bg-warning/10 text-warning border-warning/20' : 
                    'bg-surface-900 text-etth-text/50 border-surface-700'
                  }`}>
                    {selectedEvent.attribution?.status || 'UNVERIFIED'}
                  </span>
                </div>
                <div className="flex flex-col gap-2 pt-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] text-etth-text/50">Engine Confidence</span>
                    <span className="font-mono text-sm font-bold text-info">{((selectedEvent.attribution?.confidence || 0) * 100).toFixed(1)}%</span>
                  </div>
                  <div className="h-1.5 w-full bg-surface-900 rounded-full overflow-hidden border border-surface-700/50">
                    <div className="h-full bg-info" style={{ width: `${(selectedEvent.attribution?.confidence || 0) * 100}%` }}></div>
                  </div>
                  {selectedEvent.attribution?.evidence && selectedEvent.attribution.evidence.length > 0 && (
                    <div className="mt-1 p-2 rounded-sm bg-surface-900 border border-surface-700/50 text-etth-text/70 text-[10px] font-mono leading-relaxed space-y-1">
                      {selectedEvent.attribution.evidence.map((ev, i) => (
                        <div key={i}>
                          <strong className="text-etth-text">{ev.type}:</strong> {ev.value} {ev.detail && `(${ev.detail})`}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </section>

              {/* SECTION 3: DETECTION */}
              <section className="flex flex-col gap-2 pb-2 border-b border-surface-700/50">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] uppercase text-etth-text/40">Model Detection</span>
                  <span className={`font-mono text-[10px] font-semibold ${selectedEvent.detection?.prediction === 'MALICIOUS' ? 'text-accent' : 'text-success'}`}>
                    SCORE {(selectedEvent.detection?.threat_score || 0).toFixed(4)}
                  </span>
                </div>
                <div className="flex flex-col gap-1.5 font-mono text-[11px]">
                  <div className="flex items-center justify-between text-etth-text/50">
                    <span>Investigation Track:</span>
                    <span className="text-etth-text">{selectedEvent.detection?.track || 'Flow Feature Baseline'}</span>
                  </div>
                  <div className="flex items-center justify-between text-etth-text/50">
                    <span>Verdict:</span>
                    <span className={`font-semibold ${selectedEvent.detection?.prediction === 'MALICIOUS' ? 'text-accent' : 'text-success'}`}>
                      {selectedEvent.detection?.prediction || 'UNKNOWN'}
                    </span>
                  </div>
                  {selectedEvent.detection?.evidence && selectedEvent.detection.evidence.length > 0 && (
                    <div className="mt-1 p-2 rounded-sm bg-surface-900 border border-surface-700/50 text-[10px] space-y-1 text-etth-text/70">
                      {selectedEvent.detection.evidence.map((ev, i) => (
                        <div key={i}>• {ev}</div>
                      ))}
                    </div>
                  )}
                </div>
              </section>

              {/* SECTION 4: FLOW BEHAVIOUR */}
              <section className="flex flex-col gap-2 pb-2 border-b border-surface-700/50">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] uppercase text-etth-text/40">Flow Behaviour</span>
                  <span className="font-mono text-[10px] text-etth-text/40">L4 TELEMETRY</span>
                </div>
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px] pt-1">
                  <div className="p-2 rounded-sm bg-surface-900 border border-surface-700/50 flex flex-col">
                    <span className="text-[9px] uppercase text-etth-text/40">Packets</span>
                    <span className="text-etth-text font-medium mt-0.5">{selectedEvent.flow?.total_packets?.toLocaleString() || 0}</span>
                  </div>
                  <div className="p-2 rounded-sm bg-surface-900 border border-surface-700/50 flex flex-col">
                    <span className="text-[9px] uppercase text-etth-text/40">Transfer Volume</span>
                    <span className="text-etth-text font-medium mt-0.5">{selectedEvent.flow?.total_bytes?.toLocaleString() || 0} B</span>
                  </div>
                  <div className="p-2 rounded-sm bg-surface-900 border border-surface-700/50 flex flex-col">
                    <span className="text-[9px] uppercase text-etth-text/40">Active Duration</span>
                    <span className="text-etth-text font-medium mt-0.5">{(selectedEvent.flow?.duration || 0).toFixed(2)} s</span>
                  </div>
                </div>
              </section>

              {/* SECTION 5: TLS METADATA & FINGERPRINTS */}
              <section className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] uppercase text-etth-text/40">TLS Metadata & Fingerprints</span>
                  <span className="text-warning font-mono text-[10px]">Zero Decryption</span>
                </div>
                <div className="flex flex-col gap-2 font-mono text-[11px] pt-1">
                  {selectedEvent.tls?.sni_present && (
                    <div className="flex flex-col gap-1">
                      <span className="text-[9px] uppercase text-etth-text/40">Server Name Indication (SNI)</span>
                      <div className="px-2 py-1.5 rounded-sm bg-surface-900 border border-surface-700/50 text-info truncate select-all">
                        {selectedEvent.tls.sni_value || 'Present (Hidden)'}
                      </div>
                    </div>
                  )}
                  
                  <div className="grid grid-cols-2 gap-2">
                    <div className="flex flex-col gap-1">
                      <span className="text-[9px] uppercase text-etth-text/40">ALPN Protocols</span>
                      <div className="px-2 py-1.5 rounded-sm bg-surface-900 border border-surface-700/50 text-etth-text truncate">
                        {selectedEvent.tls?.alpn || 'None'}
                      </div>
                    </div>
                  </div>

                  {selectedEvent.tls?.ja4 && (
                    <div className="flex flex-col gap-1 mt-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] uppercase text-etth-text/40">JA4 Fingerprint Hash</span>
                        <button onClick={() => handleCopy(selectedEvent.tls!.ja4!, 'ja4')} className="hover:text-etth-text text-etth-text/40">
                          {copiedField === 'ja4' ? <Check className="w-3 h-3 inline text-success" /> : <Copy className="w-3 h-3 inline" />}
                        </button>
                      </div>
                      <div className="px-2 py-1.5 rounded-sm bg-surface-900 border border-surface-700/50 text-warning truncate select-all text-[10px]">
                        {selectedEvent.tls.ja4}
                      </div>
                    </div>
                  )}

                  {selectedEvent.tls?.ja3_hash && (
                    <div className="flex flex-col gap-1 mt-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] uppercase text-etth-text/40">JA3 Hash</span>
                        <button onClick={() => handleCopy(selectedEvent.tls!.ja3_hash!, 'ja3')} className="hover:text-etth-text text-etth-text/40">
                          {copiedField === 'ja3' ? <Check className="w-3 h-3 inline text-success" /> : <Copy className="w-3 h-3 inline" />}
                        </button>
                      </div>
                      <div className="px-2 py-1.5 rounded-sm bg-surface-900 border border-surface-700/50 text-etth-text truncate select-all text-[10px]">
                        {selectedEvent.tls.ja3_hash}
                      </div>
                    </div>
                  )}
                </div>
              </section>

            </div>
          </div>
        )}

      </div>
    </div>
  )
}
