import React from 'react'
import { cn } from '../../lib/utils'
import { BackButton } from './BackButton'

export interface PageHeaderProps {
  title: string
  description?: string
  actions?: React.ReactNode
  backTo?: { label: string; path: string }
  className?: string
}

export function PageHeader({ title, description, actions, backTo, className }: PageHeaderProps) {
  return (
    <div className={cn("flex items-start justify-between gap-4", className)}>
      <div className="min-w-0">
        {backTo && (
          <div className="mb-2">
            <BackButton label={backTo.label} to={backTo.path} />
          </div>
        )}
        <h1 className="text-base font-medium text-etth-text">{title}</h1>
        {description && (
          <p className="text-xs text-etth-text/40 mt-0.5">{description}</p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-2 shrink-0">
          {actions}
        </div>
      )}
    </div>
  )
}

