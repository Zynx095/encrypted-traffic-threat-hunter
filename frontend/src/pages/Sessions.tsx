import React, { useState, useEffect } from 'react'
import { PageHeader } from '../components/ui/PageHeader'
import { Badge } from '../components/ui/Badge'
import { LoadingState, EmptyState } from '../components/ui/StatusStates'
import { etthApi } from '../lib/api'
import type { Session, Target } from '../types/api'
import { Activity, Radio, StopCircle, Play, ExternalLink } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

export default function Sessions() {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState<Session[]>([])
  const [targets, setTargets] = useState<Record<string, Target>>({})
  const [loading, setLoading] = useState(true)

  const loadData = async () => {
    setLoading(true)
    try {
      const [sessData, targetData] = await Promise.all([
        etthApi.sessions.list(),
        etthApi.targets.list(true)
      ])
      // Sort sessions by start time descending
      setSessions(sessData.sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime()))

      const targetMap: Record<string, Target> = {}
      targetData.forEach(t => { targetMap[t.target_id] = t })
      setTargets(targetMap)
    } catch (err: any) {
      console.error('Failed to load sessions:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const calculateDuration = (startStr: string, endStr?: string) => {
    const start = new Date(startStr).getTime()
    const end = endStr ? new Date(endStr).getTime() : Date.now()
    const diffSec = Math.max(0, Math.floor((end - start) / 1000))
    const mins = Math.floor(diffSec / 60)
    const secs = diffSec % 60
    return `${mins}m ${secs}s`
  }

  return (
    <div className="p-4 lg:p-6 space-y-4 max-w-[1600px] mx-auto font-sans">
      <PageHeader
        title="Session Activity History"
        description="Global operational log of all monitoring and capture sessions across all targets."
      />

      {loading ? (
        <LoadingState message="Loading session activity log..." />
      ) : sessions.length === 0 ? (
        <EmptyState
          title="No Sessions Recorded"
          description="Start a Replay or Live Capture session from the Target Management or Live Monitor workspace."
        />
      ) : (
        <div className="border border-surface-700 rounded-sm bg-surface-800 overflow-hidden">
          {/* Table Header */}
          <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-surface-900 border-b border-surface-700 text-[10px] font-mono font-semibold text-etth-text/40 uppercase tracking-wider">
            <div className="col-span-2">MODE / STATUS</div>
            <div className="col-span-3">TARGET</div>
            <div className="col-span-3">SESSION ID</div>
            <div className="col-span-1 text-right">FLOWS</div>
            <div className="col-span-1 text-right">FLAGGED</div>
            <div className="col-span-1 text-right">APPROVED</div>
            <div className="col-span-1 text-right">STARTED</div>
          </div>

          {/* Table Body */}
          <div className="divide-y divide-surface-700/40 text-xs font-mono">
            {sessions.map((sess) => {
              const target = sess.target_id ? targets[sess.target_id] : null
              const duration = calculateDuration(sess.started_at, sess.ended_at)

              return (
                <div
                  key={sess.session_id}
                  onClick={() => navigate('/live', { state: { target_id: sess.target_id, initialMode: sess.source_mode } })}
                  className="grid grid-cols-12 gap-2 px-4 py-3 items-center hover:bg-surface-700/20 cursor-pointer transition-colors"
                >
                  <div className="col-span-2 flex items-center gap-1.5">
                    <Badge variant={sess.source_mode === 'LIVE' ? 'danger' : 'accent'}>
                      {sess.source_mode}
                    </Badge>
                    <Badge
                      variant={
                        sess.status === 'ACTIVE'
                          ? 'success'
                          : sess.status === 'STOPPED' || sess.status === 'COMPLETED'
                          ? 'secondary'
                          : 'warning'
                      }
                    >
                      {sess.status}
                    </Badge>
                  </div>

                  <div className="col-span-3 min-w-0">
                    <div className="text-etth-text font-semibold truncate font-sans text-xs">
                      {target ? target.display_name : 'Targetless / Global Stream'}
                    </div>
                    {target && (
                      <div className="text-[10px] text-etth-text/40 truncate">{target.hostname}</div>
                    )}
                  </div>

                  <div className="col-span-3 truncate text-etth-text/70 text-[11px]">
                    {sess.session_id}
                    <div className="text-[10px] text-etth-text/40">{duration} elapsed</div>
                  </div>

                  <div className="col-span-1 text-right text-etth-text font-medium">
                    {sess.flow_count.toLocaleString()}
                  </div>

                  <div className={`col-span-1 text-right font-bold ${sess.threat_count > 0 ? 'text-accent' : 'text-etth-text/40'}`}>
                    {sess.threat_count.toLocaleString()}
                  </div>

                  <div className="col-span-1 text-right text-success font-medium">
                    {sess.approved_flow_count.toLocaleString()}
                  </div>

                  <div className="col-span-1 text-right text-[10px] text-etth-text/40">
                    {new Date(sess.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
