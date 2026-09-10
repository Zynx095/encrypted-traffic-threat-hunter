import React from 'react'
import { cn } from '../../lib/utils'

export interface StatItem {
  label: string
  value: string | number | React.ReactNode
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info'
  mono?: boolean
}

export interface StatGroupProps {
  items: StatItem[]
  columns?: 2 | 3 | 4
  className?: string
}

const variantColors = {
  default: 'text-etth-text',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  info: 'text-info',
}

export function StatGroup({ items, columns = 3, className }: StatGroupProps) {
  const gridCols = {
    2: 'grid-cols-1 sm:grid-cols-2',
    3: 'grid-cols-1 sm:grid-cols-2 md:grid-cols-3',
    4: 'grid-cols-1 sm:grid-cols-2 md:grid-cols-4',
  }

  return (
    <div className={cn("grid gap-4", gridCols[columns], className)}>
      {items.map((item, index) => (
        <div key={index} className="flex flex-col gap-1">
          <span className="text-xs text-etth-text/50">{item.label}</span>
          <span className={cn(
            "text-base font-medium",
            variantColors[item.variant || 'default'],
            item.mono && "font-mono"
          )}>
            {item.value}
          </span>
        </div>
      ))}
    </div>
  )
}
