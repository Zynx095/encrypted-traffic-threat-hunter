import React from 'react'
import { cn } from '../../lib/utils'

export interface StatusBadgeProps {
  status: 'complete' | 'in-progress' | 'blocked' | 'pending' | 'not-started' | 'warning' | 'error'
  label?: string
  className?: string
}

const statusConfig = {
  'complete': { dot: 'bg-success', text: 'Complete' },
  'in-progress': { dot: 'bg-info animate-pulse', text: 'In Progress' },
  'blocked': { dot: 'bg-danger', text: 'Blocked' },
  'pending': { dot: 'bg-warning', text: 'Pending' },
  'not-started': { dot: 'bg-surface-500', text: 'Not Started' },
  'warning': { dot: 'bg-warning', text: 'Warning' },
  'error': { dot: 'bg-danger', text: 'Error' }
}

export function StatusBadge({ status, label, className }: StatusBadgeProps) {
  const config = statusConfig[status] || statusConfig['not-started']
  
  return (
    <div className={cn("inline-flex items-center gap-1.5 text-xs font-medium text-etth-text/70", className)}>
      <div className={cn("w-1.5 h-1.5 rounded-full", config.dot)} />
      <span>{label || config.text}</span>
    </div>
  )
}
