import React from 'react'
import { cn } from '../../lib/utils'
import { cva, type VariantProps } from 'class-variance-authority'

const metricVariants = cva(
  'bg-surface-800 border border-surface-700 rounded-sm px-3 py-2',
  {
    variants: {
      variant: {
        default: '',
        success: 'border-l-2 border-l-success',
        warning: 'border-l-2 border-l-warning',
        danger: 'border-l-2 border-l-danger',
        info: 'border-l-2 border-l-info',
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
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] text-etth-text/50 font-medium">
          {label}
        </span>
        {icon && (
          <div className="text-etth-text/20">
            {icon}
          </div>
        )}
      </div>
      <div className="text-lg font-semibold font-mono text-etth-text">
        {value}
      </div>
      {subtitle && (
        <div className="text-[11px] text-etth-text/40 mt-0.5">
          {subtitle}
        </div>
      )}
    </div>
  )
}
