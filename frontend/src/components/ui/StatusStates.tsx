import React from 'react'
import { AlertCircle, Loader2 } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from './Button'
import { cn } from '../../lib/utils'

export function LoadingState({ message = 'Loading...', className }: { message?: string, className?: string }) {
  return (
    <div className={cn("flex items-center justify-center py-8", className)}>
      <div className="flex items-center gap-2 text-etth-text/50">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span className="text-sm">{message}</span>
      </div>
    </div>
  )
}

export function EmptyState({ title, description, icon, onRetry, className }: { title: string; description?: string; icon?: LucideIcon; onRetry?: () => void, className?: string }) {
  const IconComponent = icon || AlertCircle
  return (
    <div className={cn("flex flex-col items-center justify-center py-8 text-center", className)}>
      <IconComponent className="w-5 h-5 text-etth-text/30 mb-3" />
      <p className="text-sm text-etth-text/60 mb-1">{title}</p>
      {description && <p className="text-xs text-etth-text/40 max-w-sm mb-3">{description}</p>}
      {onRetry && (
        <Button onClick={onRetry} variant="secondary" size="sm">
          Retry
        </Button>
      )}
    </div>
  )
}

export function ErrorState({ message, onRetry, className }: { message: string; onRetry?: () => void, className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center py-8 text-center", className)}>
      <AlertCircle className="w-5 h-5 text-danger/70 mb-3" />
      <p className="text-sm text-etth-text/60 mb-1">Failed to load</p>
      <p className="text-xs text-etth-text/40 max-w-sm mb-3">{message}</p>
      {onRetry && (
        <Button onClick={onRetry} variant="secondary" size="sm">
          Retry
        </Button>
      )}
    </div>
  )
}

export function MetricSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn("bg-surface-800 border border-surface-700 rounded-sm p-3 h-[72px]", className)}>
      <div className="h-3 w-20 bg-surface-700 rounded-sm mb-2 animate-pulse" />
      <div className="h-5 w-12 bg-surface-700 rounded-sm animate-pulse" />
    </div>
  )
}

export function TableSkeleton({ rows = 5, className }: { rows?: number, className?: string }) {
  return (
    <div className={cn("w-full border border-surface-700 rounded-sm overflow-hidden bg-surface-800", className)}>
      <div className="bg-surface-700/30 h-9 w-full border-b border-surface-700" />
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center px-3 gap-4 border-b border-surface-700/50 last:border-0 h-10">
          <div className="h-3 bg-surface-700/50 rounded-sm flex-1 animate-pulse" />
          <div className="h-3 bg-surface-700/50 rounded-sm flex-1 hidden sm:block animate-pulse" />
          <div className="h-3 bg-surface-700/50 rounded-sm w-16 hidden md:block animate-pulse" />
        </div>
      ))}
    </div>
  )
}

export function CardSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn("border border-surface-700 rounded-sm overflow-hidden bg-surface-800", className)}>
      <div className="px-4 py-3 border-b border-surface-700">
        <div className="h-4 w-1/3 bg-surface-700/50 rounded-sm animate-pulse" />
      </div>
      <div className="p-4 space-y-3">
        <div className="h-3 w-full bg-surface-700/50 rounded-sm animate-pulse" />
        <div className="h-3 w-5/6 bg-surface-700/50 rounded-sm animate-pulse" />
        <div className="h-3 w-4/6 bg-surface-700/50 rounded-sm animate-pulse" />
      </div>
    </div>
  )
}
