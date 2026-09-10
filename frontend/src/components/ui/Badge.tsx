import { cn } from '../../lib/utils'
import { cva, type VariantProps } from 'class-variance-authority'

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-surface-600 text-etth-text hover:bg-surface-600/80',
        secondary: 'border-transparent bg-surface-700 text-etth-text/70 hover:bg-surface-700/80',
        danger: 'border-transparent bg-danger/15 text-danger hover:bg-danger/25',
        outline: 'border-surface-600 text-etth-text/70 hover:bg-surface-800',
        success: 'border-transparent bg-success/15 text-success hover:bg-success/25',
        warning: 'border-transparent bg-warning/15 text-warning hover:bg-warning/25',
        info: 'border-transparent bg-info/15 text-info hover:bg-info/25',
        accent: 'border-transparent bg-etth-accent/15 text-etth-accent hover:bg-etth-accent/25',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
)

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {
  children: React.ReactNode
}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}
