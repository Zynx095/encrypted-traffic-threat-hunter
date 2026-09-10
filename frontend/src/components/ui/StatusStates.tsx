import React from 'react'
import { AlertCircle, Loader2 } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from './Button'
import { cn } from '../../lib/utils'

export function LoadingState({ message = 'Loading...', className }: { message?: string, className?: string }) {
  return (
    <div className={cn("flex items-center justify-center py-12", className)}>
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="w-8 h-8 text-etth-accent animate-spin" />
        <p className="text-sm text-etth-text/50">{message}</p>
      </div>
    </div>
  )
}

export function EmptyState({ title, description, icon, onRetry, className }: { title: string; description?: string; icon?: LucideIcon; onRetry?: () => void, className?: string }) {
  const IconComponent = icon || AlertCircle
  return (
    <div className={cn("flex flex-col items-center justify-center py-12 text-center", className)}>
      <div className="w-12 h-12 rounded-full bg-surface-700 flex items-center justify-center mb-4">
        <IconComponent className="w-6 h-6 text-etth-text/50" />
      </div>
      <h3 className="text-sm font-medium text-etth-text mb-1">{title}</h3>
      {description && <p className="text-xs text-etth-text/50 max-w-sm mb-4">{description}</p>}
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
    <div className={cn("flex flex-col items-center justify-center py-12 text-center", className)}>
      <AlertCircle className="w-12 h-12 text-danger mb-4" />
      <h3 className="text-sm font-medium text-etth-text mb-1">Error</h3>
      <p className="text-xs text-etth-text/50 max-w-sm mb-4">{message}</p>
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
    <div className={cn("bg-surface-700/50 animate-pulse rounded-sm p-4 h-[104px] w-full", className)}>
      <div className="flex justify-between items-start mb-2">
        <div className="h-3 w-24 bg-surface-600 rounded"></div>
        <div className="h-4 w-4 bg-surface-600 rounded"></div>
      </div>
      <div className="h-8 w-16 bg-surface-600 rounded mb-1"></div>
      <div className="h-3 w-32 bg-surface-600 rounded"></div>
    </div>
  )
}

export function TableSkeleton({ rows = 5, className }: { rows?: number, className?: string }) {
  return (
    <div className={cn("w-full border border-surface-700 rounded-sm overflow-hidden bg-surface-800", className)}>
      <div className="bg-surface-700/50 h-10 w-full animate-pulse border-b border-surface-700"></div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex p-4 gap-4 border-b border-surface-700/50 last:border-0 h-14 animate-pulse">
          <div className="h-4 bg-surface-700/50 rounded flex-1"></div>
          <div className="h-4 bg-surface-700/50 rounded flex-1 hidden sm:block"></div>
          <div className="h-4 bg-surface-700/50 rounded flex-1 hidden md:block"></div>
        </div>
      ))}
    </div>
  )
}

export function CardSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn("border border-surface-700 rounded-sm overflow-hidden bg-surface-800", className)}>
      <div className="p-6 border-b border-surface-700 animate-pulse">
        <div className="h-5 w-1/3 bg-surface-700/50 rounded mb-2"></div>
        <div className="h-4 w-2/3 bg-surface-700/50 rounded"></div>
      </div>
      <div className="p-6 space-y-4 animate-pulse">
        <div className="h-4 w-full bg-surface-700/50 rounded"></div>
        <div className="h-4 w-5/6 bg-surface-700/50 rounded"></div>
        <div className="h-4 w-4/6 bg-surface-700/50 rounded"></div>
      </div>
    </div>
  )
}
