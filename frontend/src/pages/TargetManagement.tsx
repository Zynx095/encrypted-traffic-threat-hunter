import React, { useState, useEffect } from 'react'
import { Plus, Globe, Server, Radio, StopCircle, Trash2, RefreshCw, Activity, Layers, ExternalLink } from 'lucide-react'
import { PageHeader } from '../components/ui/PageHeader'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { LoadingState, EmptyState } from '../components/ui/StatusStates'
import { etthApi } from '../lib/api'
import type { Target, Session, TargetType, AttributionStatus } from '../types/api'
import { useNavigate } from 'react-router-dom'
import { ShihTzuMark } from '../components/ui/ShihTzuMark'


export default function TargetManagement() {
  const navigate = useNavigate()
  const [targets, setTargets] = useState<Target[]>([])
  const [loadingTargets, setLoadingTargets] = useState(true)
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null)
  const [sessions, setSessions] = useState<Session[]>([])
  const [loadingSessions, setLoadingSessions] = useState(false)
  const [attributionFilter, setAttributionFilter] = useState<AttributionStatus | 'ALL'>('ALL')

  const [showAddModal, setShowAddModal] = useState(false)
  const [hostname, setHostname] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [targetType, setTargetType] = useState<TargetType>('WEB')
  const [aliasesStr, setAliasesStr] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const loadTargets = async () => {
    setLoadingTargets(true)
    try {
      const data = await etthApi.targets.list(true)
      setTargets(data)
      if (data.length > 0 && !selectedTarget) {
        setSelectedTarget(data[0])
      }
    } catch (err: any) {
      console.error('Failed to load targets:', err)
      setErrorMsg(err.message || 'Failed to load targets')
    } finally {
      setLoadingTargets(false)
    }
  }

  const loadSessions = async (targetId: string) => {
    setLoadingSessions(true)
    try {
      const data = await etthApi.sessions.listByTarget(targetId)
      setSessions(data)
    } catch (err: any) {
      console.error('Failed to load sessions:', err)
    } finally {
      setLoadingSessions(false)
    }
  }

  useEffect(() => {
    loadTargets()
  }, [])

  useEffect(() => {
    if (selectedTarget) {
      loadSessions(selectedTarget.target_id)
    }
  }, [selectedTarget])

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!hostname.trim()) {
      setErrorMsg('Hostname is required')
      return
    }
    setIsSubmitting(true)
    setErrorMsg(null)
    const aliases = aliasesStr.split(',').map(s => s.trim()).filter(Boolean)
    try {
      const created = await etthApi.targets.create({
        hostname: hostname.trim(),
        display_name: displayName.trim() || undefined,
        target_type: targetType,
        aliases,
      })
      setShowAddModal(false)
      setHostname('')
      setDisplayName('')
      setAliasesStr('')
      setTargetType('WEB')
      await loadTargets()
      setSelectedTarget(created)
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to create target')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleDeleteTarget = async (targetId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm('Disable this target? Historical sessions are preserved.')) return
    try {
      await etthApi.targets.delete(targetId)
      await loadTargets()
      if (selectedTarget?.target_id === targetId) {
        setSelectedTarget(null)
      }
    } catch (err: any) {
      alert(err.message || 'Failed to disable target')
    }
  }

  const handleStopSession = async (sessionId: string) => {
    try {
      await etthApi.sessions.stop(sessionId)
      if (selectedTarget) {
        await loadSessions(selectedTarget.target_id)
      }
    } catch (err: any) {
      alert(err.message || 'Failed to stop session')
    }
  }

  const handleStartLiveForTarget = (target: Target, e: React.MouseEvent) => {
    e.stopPropagation()
    navigate('/live', { state: { target_id: target.target_id, target_name: target.display_name, initialMode: 'LIVE' } })
  }

  const handleStartReplayForTarget = (target: Target, e: React.MouseEvent) => {
    e.stopPropagation()
    navigate('/live', { state: { target_id: target.target_id, target_name: target.display_name, initialMode: 'REPLAY' } })
  }

  return (
    <div className="p-4 lg:p-6 space-y-4 max-w-[1600px] mx-auto font-sans">
      <PageHeader
        title="Target Management & Monitored Assets"
        description="Configure monitored network assets and view target attribution sessions."
        actions={
          <Button onClick={() => setShowAddModal(true)} size="sm">
            <Plus className="w-3.5 h-3.5 mr-1" /> Add Target
          </Button>
        }
      />

      {/* Attribution methodology banner */}
      <div className="text-[11px] font-mono text-etth-text/50 border-l-2 border-accent pl-3 py-1 bg-surface-800/40 rounded-r-sm">
        Target attribution correlates observable SNI, ALPN, and DNS metadata without TLS decryption.
      </div>

      {loadingTargets ? (
        <LoadingState message="Loading target workspace..." />
      ) : targets.length === 0 ? (
        <EmptyState title="No Targets Monitored" description="Add a target hostname (e.g. youtube.com) to begin monitoring sessions." />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Target List Workspace */}
          <div className="lg:col-span-5 border border-surface-700 rounded-sm bg-surface-800 overflow-hidden">
            <div className="px-4 py-2.5 border-b border-surface-700 bg-surface-900/50 flex items-center justify-between">
              <span className="text-xs font-semibold text-etth-text uppercase tracking-wider">Monitored Assets ({targets.length})</span>
            </div>

            <div className="divide-y divide-surface-700/50">
              {targets.map((tgt) => {
                const isSelected = selectedTarget?.target_id === tgt.target_id
                return (
                  <div
                    key={tgt.target_id}
                    onClick={() => setSelectedTarget(tgt)}
                    className={`p-3 cursor-pointer transition-colors ${
                      isSelected ? 'bg-surface-700/60 border-l-2 border-accent' : 'hover:bg-surface-700/20'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          {tgt.target_type === 'WEB' ? (
                            <Globe className="w-3.5 h-3.5 text-accent shrink-0" />
                          ) : (
                            <Server className="w-3.5 h-3.5 text-info shrink-0" />
                          )}
                          <span className="text-xs font-semibold text-etth-text truncate">{tgt.display_name}</span>
                          <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                            tgt.enabled ? 'bg-success/15 text-success' : 'bg-surface-700 text-etth-text/40'
                          }`}>
                            {tgt.enabled ? 'ACTIVE' : 'DISABLED'}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-etth-text/50 truncate mt-0.5">{tgt.hostname}</div>
                        {tgt.aliases && tgt.aliases.length > 0 && (
                          <div className="text-[10px] font-mono text-etth-text/30 truncate mt-0.5">
                            Aliases: {tgt.aliases.join(', ')}
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-1 shrink-0">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={(e) => handleStartLiveForTarget(tgt, e)}
                          className="h-6 text-[10px] px-2 text-danger hover:bg-danger/10"
                        >
                          <Radio className="w-3 h-3 mr-1" /> Live
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={(e) => handleStartReplayForTarget(tgt, e)}
                          className="h-6 text-[10px] px-2 text-etth-text/60 hover:text-etth-text"
                        >
                          Replay
                        </Button>
                        <button
                          onClick={(e) => handleDeleteTarget(tgt.target_id, e)}
                          className="p-1 text-etth-text/30 hover:text-danger transition-colors"
                          title="Disable target"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Selected Target Workspace Details */}
          {selectedTarget && (
            <div className="lg:col-span-7 border border-surface-700 rounded-sm bg-surface-800 overflow-hidden">
              <div className="p-4 border-b border-surface-700 bg-surface-900/50 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold text-etth-text">{selectedTarget.display_name}</h2>
                    <Badge variant="secondary">{selectedTarget.target_type}</Badge>
                  </div>
                  <div className="text-xs font-mono text-etth-text/50 mt-0.5">
                    {selectedTarget.hostname} • <span className="text-[10px] text-etth-text/30">{selectedTarget.target_id}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Button size="sm" variant="default" onClick={(e) => handleStartLiveForTarget(selectedTarget, e)}>
                    <Radio className="w-3.5 h-3.5 mr-1 text-white" /> Start Live
                  </Button>
                  <Button size="sm" variant="secondary" onClick={(e) => handleStartReplayForTarget(selectedTarget, e)}>
                    Start Replay
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => loadSessions(selectedTarget.target_id)}>
                    <RefreshCw className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </div>

              {/* Attribution Status Filter Tabs */}
              <div className="flex items-center gap-2 px-4 py-2 border-b border-surface-700 bg-surface-900/30 text-xs font-mono">
                <span className="text-etth-text/40 text-[10px]">ATTRIBUTION FILTER:</span>
                {(['ALL', 'ATTRIBUTED', 'PROBABLE', 'UNKNOWN', 'NOT_MATCHED'] as const).map((filterKey) => (
                  <button
                    key={filterKey}
                    onClick={() => setAttributionFilter(filterKey)}
                    className={`px-2 py-0.5 rounded-sm text-[10px] transition-colors ${
                      attributionFilter === filterKey
                        ? 'bg-surface-600 text-etth-text font-semibold'
                        : 'text-etth-text/40 hover:text-etth-text/80'
                    }`}
                  >
                    {filterKey}
                  </button>
                ))}
              </div>

              {/* Session Activity Table */}
              <div className="p-4 space-y-3">
                <div className="text-xs font-semibold text-etth-text uppercase tracking-wider">Target Session History</div>

                {loadingSessions ? (
                  <LoadingState message="Loading target session activity..." />
                ) : sessions.length === 0 ? (
                  <EmptyState title="No Recorded Sessions" description="Run a Replay or Live Capture session associated with this target." />
                ) : (
                  <div className="border border-surface-700 rounded-sm overflow-hidden text-xs font-mono">
                    <div className="grid grid-cols-12 gap-2 px-3 py-2 bg-surface-900 text-[10px] text-etth-text/40 font-semibold uppercase border-b border-surface-700">
                      <div className="col-span-3">MODE / STATUS</div>
                      <div className="col-span-3">SESSION ID</div>
                      <div className="col-span-2 text-right">FLOWS</div>
                      <div className="col-span-2 text-right">THREATS</div>
                      <div className="col-span-2 text-right">STARTED</div>
                    </div>

                    <div className="divide-y divide-surface-700/40">
                      {sessions.map((sess) => (
                        <div key={sess.session_id} className="grid grid-cols-12 gap-2 px-3 py-2.5 items-center hover:bg-surface-700/20">
                          <div className="col-span-3 flex items-center gap-1.5">
                            <Badge variant={sess.source_mode === 'LIVE' ? 'danger' : 'accent'}>{sess.source_mode}</Badge>
                            <span className="text-[10px] text-etth-text/70">{sess.status}</span>
                          </div>
                          <div className="col-span-3 truncate text-etth-text/80">{sess.session_id}</div>
                          <div className="col-span-2 text-right text-etth-text">{sess.flow_count.toLocaleString()}</div>
                          <div className={`col-span-2 text-right font-bold ${sess.threat_count > 0 ? 'text-accent' : 'text-etth-text/40'}`}>
                            {sess.threat_count}
                          </div>
                          <div className="col-span-2 text-right text-[10px] text-etth-text/40">
                            {new Date(sess.started_at).toLocaleDateString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Modal for Adding Target */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4" onClick={() => setShowAddModal(false)}>
          <div className="w-full max-w-md bg-surface-800 border border-surface-700 rounded-sm p-5 space-y-4 font-sans" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-etth-text uppercase tracking-wider">Add Monitored Target</h3>

            {errorMsg && (
              <div className="px-3 py-2 rounded-sm bg-danger/10 border border-danger/20 text-danger text-xs font-mono">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleCreateTarget} className="space-y-3">
              <div>
                <label className="block text-xs text-etth-text/60 mb-1">
                  Hostname <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. youtube.com"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-sm bg-surface-900 border border-surface-600 text-etth-text text-xs focus:outline-none focus:border-accent font-mono"
                  required
                />
              </div>

              <div>
                <label className="block text-xs text-etth-text/60 mb-1">Display Name</label>
                <input
                  type="text"
                  placeholder="e.g. YouTube"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-sm bg-surface-900 border border-surface-600 text-etth-text text-xs focus:outline-none focus:border-accent"
                />
              </div>

              <div>
                <label className="block text-xs text-etth-text/60 mb-1">Aliases (comma-separated)</label>
                <input
                  type="text"
                  placeholder="e.g. googlevideo.com, ytimg.com"
                  value={aliasesStr}
                  onChange={(e) => setAliasesStr(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-sm bg-surface-900 border border-surface-600 text-etth-text text-xs focus:outline-none focus:border-accent font-mono"
                />
              </div>

              <div>
                <label className="block text-xs text-etth-text/60 mb-1">Target Type</label>
                <select
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value as TargetType)}
                  className="w-full px-3 py-1.5 rounded-sm bg-surface-900 border border-surface-600 text-etth-text text-xs focus:outline-none focus:border-accent font-mono"
                >
                  <option value="WEB">WEB</option>
                  <option value="CUSTOM">CUSTOM</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <Button type="button" variant="ghost" size="sm" onClick={() => setShowAddModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm" disabled={isSubmitting}>
                  {isSubmitting ? 'Creating...' : 'Create Target'}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
