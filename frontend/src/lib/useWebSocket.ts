import { useState, useEffect, useRef, useCallback } from 'react'
import type { LiveFlowEvent, WSClientMessage, WSServerMessage } from '../types/api'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/live-stream'

export interface UseWebSocketReturn {
  isConnected: boolean
  streamState: 'RUNNING' | 'PAUSED' | 'STOPPED'
  speed: number
  events: LiveFlowEvent[]
  error: string | null
  startReplay: (speed?: number, threatsOnly?: boolean) => void
  pauseReplay: () => void
  resumeReplay: () => void
  setSpeed: (speed: number) => void
  clearEvents: () => void
}

export function useWebSocket(maxEvents = 100): UseWebSocketReturn {
  const [isConnected, setIsConnected] = useState(false)
  const [streamState, setStreamState] = useState<'RUNNING' | 'PAUSED' | 'STOPPED'>('STOPPED')
  const [speed, setSpeedState] = useState(1.0)
  const [events, setEvents] = useState<LiveFlowEvent[]>([])
  const [error, setError] = useState<string | null>(null)

  const socketRef = useRef<WebSocket | null>(null)

  const sendMessage = useCallback((msg: WSClientMessage) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify(msg))
    }
  }, [])

  useEffect(() => {
    let socket: WebSocket | null = null
    let reconnectTimer: NodeJS.Timeout

    const connect = () => {
      try {
        socket = new WebSocket(WS_URL)
        socketRef.current = socket

        socket.onopen = () => {
          setIsConnected(true)
          setError(null)
          // Automatically start streaming on connection
          socket?.send(JSON.stringify({ action: 'START_REPLAY', speed: 1.0, threats_only: false }))
        }

        socket.onmessage = (event) => {
          try {
            const data: WSServerMessage = JSON.parse(event.data)
            if (data.type === 'CONNECTED') {
              setIsConnected(true)
              if (data.state) setStreamState(data.state as any)
            } else if (data.type === 'STREAM_STATE') {
              setStreamState(data.state)
              if (data.speed) setSpeedState(data.speed)
            } else if (data.type === 'FLOW_EVENT') {
              setEvents((prev) => [data.data, ...prev].slice(0, maxEvents))
            } else if (data.type === 'ERROR') {
              setError(data.message)
            }
          } catch (e) {
            console.error('Failed to parse WebSocket message:', e)
          }
        }

        socket.onerror = (err) => {
          console.warn('WebSocket connection error:', err)
          setError('WebSocket connection error')
          setIsConnected(false)
        }

        socket.onclose = () => {
          setIsConnected(false)
          setStreamState('STOPPED')
          // Auto-reconnect after 3 seconds
          reconnectTimer = setTimeout(connect, 3000)
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : 'WebSocket creation failed')
        reconnectTimer = setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      clearTimeout(reconnectTimer)
      if (socket) {
        socket.close()
      }
    }
  }, [maxEvents])

  const startReplay = useCallback((speed = 1.0, threatsOnly = false) => {
    sendMessage({ action: 'START_REPLAY', speed, threats_only: threatsOnly })
  }, [sendMessage])

  const pauseReplay = useCallback(() => {
    sendMessage({ action: 'PAUSE_REPLAY' })
  }, [sendMessage])

  const resumeReplay = useCallback(() => {
    sendMessage({ action: 'RESUME_REPLAY' })
  }, [sendMessage])

  const setSpeed = useCallback((newSpeed: number) => {
    setSpeedState(newSpeed)
    sendMessage({ action: 'SET_SPEED', speed: newSpeed })
  }, [sendMessage])

  const clearEvents = useCallback(() => {
    setEvents([])
  }, [])

  return {
    isConnected,
    streamState,
    speed,
    events,
    error,
    startReplay,
    pauseReplay,
    resumeReplay,
    setSpeed,
    clearEvents,
  }
}
