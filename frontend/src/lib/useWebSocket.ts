import { useState, useEffect, useRef, useCallback } from 'react'
import type { ETTHStreamEvent, WSClientMessage, ModelTrack, StreamState, StreamTelemetry, NetworkInterface, CaptureStatus } from '../types/api'
import { useETTHStore } from '../store/etthStore'
import { etthApi } from './api'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/live-stream'

export interface UseWebSocketReturn {
  isConnected: boolean
  streamState: StreamState
  speed: number
  track: ModelTrack
  streamId: string
  source: string
  mode: 'REPLAY' | 'LIVE'
  events: ETTHStreamEvent[]
  telemetry: StreamTelemetry | null
  error: string | null
  interfaces: NetworkInterface[]
  selectedInterface: string
  captureStatus: CaptureStatus
  startReplay: (speed?: number, threatsOnly?: boolean, track?: ModelTrack, targetId?: string) => void
  startLive: (iface?: string, track?: ModelTrack, targetId?: string) => void
  pauseReplay: () => void
  resumeReplay: () => void
  stopReplay: () => void
  stopLive: () => void
  setSpeed: (speed: number) => void
  setTrack: (track: ModelTrack) => void
  selectInterface: (iface: string) => void
  clearEvents: () => void
  fetchInterfaces: () => Promise<void>
}

export function useWebSocket(maxEvents = 100): UseWebSocketReturn {
  const [isConnected, setIsConnected] = useState(false)
  const [streamState, setStreamState] = useState<StreamState>('IDLE')
  const [speed, setSpeedState] = useState(1.0)
  const [track, setTrackState] = useState<ModelTrack>('A_FLOW')
  const [streamId, setStreamId] = useState('')
  const [source, setSource] = useState('DS-008')
  const [mode, setMode] = useState<'REPLAY' | 'LIVE'>('REPLAY')
  const [events, setEvents] = useState<ETTHStreamEvent[]>([])
  const [telemetry, setTelemetry] = useState<StreamTelemetry | null>(null)
  const [error, setError] = useState<string | null>(null)
  
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [selectedInterface, setSelectedInterface] = useState<string>('')
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus>('READY')

  const socketRef = useRef<WebSocket | null>(null)
  const lastSequenceRef = useRef<number>(0)
  const lastStreamIdRef = useRef<string>('')
  const retryCountRef = useRef<number>(0)

  const setStoreWSConnected = useETTHStore((s) => s.setWSConnected)
  const addStoreLiveEvent = useETTHStore((s) => s.addLiveEvent)
  const setStoreTelemetry = useETTHStore((s) => s.setTelemetry)

  const sendMessage = useCallback((msg: WSClientMessage) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify(msg))
    }
  }, [])

  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await etthApi.liveStream.interfaces()
      if (res.available) {
        setInterfaces(res.interfaces || [])
        setCaptureStatus(res.status || 'READY')
        if (res.interfaces && res.interfaces.length > 0 && !selectedInterface) {
          setSelectedInterface(res.interfaces[0].id)
        }
      } else {
        setCaptureStatus('CAPTURE_UNAVAILABLE')
        if (res.error_message) setError(res.error_message)
      }
    } catch (e) {
      setCaptureStatus('CAPTURE_UNAVAILABLE')
    }
  }, [selectedInterface])

  useEffect(() => {
    fetchInterfaces()
  }, [fetchInterfaces])

  useEffect(() => {
    let socket: WebSocket | null = null
    let reconnectTimer: NodeJS.Timeout

    const connect = () => {
      try {
        socket = new WebSocket(WS_URL)
        socketRef.current = socket

        socket.onopen = () => {
          setIsConnected(true)
          setStoreWSConnected(true)
          setError(null)
          retryCountRef.current = 0
          socket?.send(JSON.stringify({ action: 'START_REPLAY', speed: 1.0, threats_only: false, track: 'A_FLOW' }))
        }

        socket.onmessage = (event) => {
          try {
            const data: ETTHStreamEvent = JSON.parse(event.data)
            
            if (!data || !data.event_type) return

            // Handle telemetry payload if attached or in stream.telemetry
            if (data.telemetry) {
              setTelemetry(data.telemetry)
              setStoreTelemetry(data.telemetry)
              setStreamState(data.telemetry.state)
              if (data.telemetry.playback_speed) setSpeedState(data.telemetry.playback_speed)
              if (data.telemetry.selected_track) setTrackState(data.telemetry.selected_track)
              if (data.telemetry.stream_id) setStreamId(data.telemetry.stream_id)
              if (data.telemetry.source) setSource(data.telemetry.source)
              if (data.telemetry.mode) setMode(data.telemetry.mode)
            }

            // Handle Stream ID change / Sequence duplicate filtering
            if (data.stream_id && data.stream_id !== lastStreamIdRef.current) {
              lastStreamIdRef.current = data.stream_id
              lastSequenceRef.current = 0
            }

            // Drop stale / duplicate sequences within the same stream (except telemetry events which share sequence numbers or status updates)
            if (data.event_type !== 'stream.telemetry' && data.sequence <= lastSequenceRef.current && data.sequence > 0) {
              return
            }
            if (data.sequence > 0) {
              lastSequenceRef.current = data.sequence
            }

            // Update top-level stream state
            if (data.stream_id) setStreamId(data.stream_id)
            if (data.source) setSource(data.source)
            if (data.mode) setMode(data.mode)

            // Lifecycle Events vs Flow Events
            switch (data.event_type) {
              case 'stream.started':
                setStreamState('PLAYING')
                if (data.metadata?.speed) setSpeedState(data.metadata.speed)
                break
              case 'stream.paused':
                setStreamState('PAUSED')
                break
              case 'stream.resumed':
                setStreamState('PLAYING')
                break
              case 'stream.stopped':
                setStreamState('STOPPED')
                break
              case 'stream.completed':
                setStreamState('COMPLETED')
                break
              case 'stream.error':
                setStreamState('ERROR')
                setError(data.metadata?.error_message || 'Stream error occurred')
                break
              case 'flow.detected':
                if (data.flow) {
                  if (data.detection?.track) setTrackState(data.detection.track)
                  setEvents((prev) => [data, ...prev].slice(0, maxEvents))
                  addStoreLiveEvent(data)
                }
                break
              case 'stream.telemetry':
                // Telemetry state processed above
                break
            }
          } catch (e) {
            console.warn('Failed to parse WebSocket message:', e)
          }
        }

        socket.onerror = () => {
          setError('WebSocket connection error')
          setIsConnected(false)
          setStoreWSConnected(false)
        }

        socket.onclose = () => {
          setIsConnected(false)
          setStoreWSConnected(false)
          setStreamState('STOPPED')
          // Exponential backoff up to 5 retries (max 16s delay)
          if (retryCountRef.current < 5) {
            const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 16000)
            retryCountRef.current += 1
            reconnectTimer = setTimeout(connect, delay)
          }
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : 'WebSocket creation failed')
      }
    }

    connect()

    return () => {
      clearTimeout(reconnectTimer)
      if (socket) {
        socket.close()
      }
    }
  }, [maxEvents, addStoreLiveEvent, setStoreTelemetry, setStoreWSConnected])

  const startReplay = useCallback((newSpeed = 1.0, threatsOnly = false, newTrack: ModelTrack = 'A_FLOW', targetId?: string) => {
    sendMessage({ action: 'START_REPLAY', speed: newSpeed, threats_only: threatsOnly, track: newTrack, target_id: targetId })
  }, [sendMessage])

  const startLive = useCallback((iface?: string, newTrack: ModelTrack = 'A_FLOW', targetId?: string) => {
    const targetIface = iface || selectedInterface
    sendMessage({ action: 'START_LIVE', interface: targetIface, track: newTrack, target_id: targetId })
  }, [sendMessage, selectedInterface])

  const pauseReplay = useCallback(() => {
    sendMessage({ action: 'PAUSE_REPLAY' })
  }, [sendMessage])

  const resumeReplay = useCallback(() => {
    sendMessage({ action: 'RESUME_REPLAY' })
  }, [sendMessage])

  const stopReplay = useCallback(() => {
    sendMessage({ action: 'STOP_REPLAY' })
  }, [sendMessage])

  const stopLive = useCallback(() => {
    sendMessage({ action: 'STOP_LIVE' })
  }, [sendMessage])

  const setSpeed = useCallback((newSpeed: number) => {
    setSpeedState(newSpeed)
    sendMessage({ action: 'SET_SPEED', speed: newSpeed })
  }, [sendMessage])

  const setTrack = useCallback((newTrack: ModelTrack) => {
    setTrackState(newTrack)
    sendMessage({ action: 'SET_TRACK', track: newTrack })
  }, [sendMessage])

  const selectInterface = useCallback((iface: string) => {
    setSelectedInterface(iface)
    sendMessage({ action: 'SELECT_INTERFACE', interface: iface })
  }, [sendMessage])

  const clearEvents = useCallback(() => {
    setEvents([])
  }, [])

  return {
    isConnected,
    streamState,
    speed,
    track,
    streamId,
    source,
    mode,
    events,
    telemetry,
    error,
    interfaces,
    selectedInterface,
    captureStatus,
    startReplay,
    startLive,
    pauseReplay,
    resumeReplay,
    stopReplay,
    stopLive,
    setSpeed,
    setTrack,
    selectInterface,
    clearEvents,
    fetchInterfaces,
  }
}
