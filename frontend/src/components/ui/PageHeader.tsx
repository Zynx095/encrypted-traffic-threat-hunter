import React from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft } from 'lucide-react'
import { Button } from './Button'
import { cn } from '../../lib/utils'

export interface PageHeaderProps {
  title: string
  description?: string
  actions?: React.ReactNode
  backTo?: { label: string; path: string }
  className?: string
}

export function PageHeader({ title, description, actions, backTo, className }: PageHeaderProps) {
  const navigate = useNavigate()

  return (
    <div className={cn("flex flex-col md:flex-row md:items-start justify-between gap-4 mb-6", className)}>
      <div className="flex flex-col gap-1">
        {backTo && (
          <Button
            variant="ghost"
            size="sm"
            className="w-fit -ml-3 mb-2 text-etth-text/50 hover:text-etth-text"
            onClick={() => navigate(backTo.path)}
          >
            <ChevronLeft className="w-4 h-4 mr-1" />
            {backTo.label}
          </Button>
        )}
        <h1 className="text-xl font-semibold text-etth-text">{title}</h1>
        {description && (
          <p className="text-sm text-etth-text/50">{description}</p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-2">
          {actions}
        </div>
      )}
    </div>
  )
}
