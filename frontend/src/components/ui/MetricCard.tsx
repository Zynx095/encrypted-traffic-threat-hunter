import React from 'react'
import { cn } from '../../lib/utils'
import { cva, type VariantProps } from 'class-variance-authority'

const metricVariants = cva(
  'relative overflow-hidden bg-surface-800 border rounded-sm px-3 py-2.5 transition-none group',
  {
    variants: {
      variant: {
        default: 'border-surface-700',
        success: 'border-surface-700 border-l-2 border-l-success',
        warning: 'border-surface-700 border-l-2 border-l-warning',
        danger: 'border-surface-700 border-l-2 border-l-danger',
        info: 'border-surface-700 border-l-2 border-l-info',
      },
    },
    defaultVariants: { variant: 'default' },
  }
)

export interface MetricCardProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof metricVariants> {
  label: string
  value: string | number
  subtitle?: string
  trend?: 'up' | 'down' | 'neutral'
  icon?: React.ReactNode
}

export function MetricCard({ label, value, subtitle, trend, icon, variant, className, ...props }: MetricCardProps) {
  return (
    <div className={cn(metricVariants({ variant }), className)} {...props}>
      <div className="flex items-start justify-between mb-2">
        <span className="text-xs uppercase tracking-wide text-etth-text/50 font-medium">
          {label}
        </span>
        {icon && (
          <div className="text-etth-text/30 group-hover:text-etth-text/50 transition-colors">
            {icon}
          </div>
        )}
      </div>
      <div className="text-2xl font-semibold font-mono text-etth-text mb-1">
        {value}
      </div>
      {subtitle && (
        <div className="text-xs text-etth-text/40">
          {subtitle}
        </div>
      )}
    </div>
  )
}
