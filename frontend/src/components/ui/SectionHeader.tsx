import React from 'react'
import { cn } from '../../lib/utils'

export interface SectionHeaderProps {
  title: string
  description?: string
  actions?: React.ReactNode
  className?: string
}

export function SectionHeader({ title, description, actions, className }: SectionHeaderProps) {
  return (
    <div className={cn("w-full mb-4", className)}>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xs uppercase tracking-wider text-etth-text/40 font-medium">
            {title}
          </h2>
          {description && (
            <p className="mt-1 text-xs text-etth-text/30">{description}</p>
          )}
        </div>
        {actions && (
          <div className="flex items-center gap-2">
            {actions}
          </div>
        )}
      </div>
      <div className="h-px w-full bg-surface-700/50 mt-3" />
    </div>
  )
}
