import { cn } from '../../lib/utils'
import { cva, type VariantProps } from 'class-variance-authority'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 rounded-sm font-medium text-sm transition-colors focus:outline-none focus:ring-1 focus:ring-offset-1 focus:ring-offset-surface-900 disabled:opacity-50 disabled:pointer-events-none',
  {
    variants: {
      variant: {
        default: 'bg-etth-accent text-white hover:bg-etth-accent/90 focus:ring-etth-accent',
        secondary: 'bg-surface-700 text-etth-text border border-surface-600 hover:bg-surface-600 focus:ring-surface-500',
        ghost: 'text-etth-text/60 hover:bg-surface-700/50 hover:text-etth-text focus:ring-surface-500',
        outline: 'border border-surface-600 text-etth-text/80 hover:bg-surface-700/50 focus:ring-surface-500',
        danger: 'bg-danger/15 text-danger hover:bg-danger/25 focus:ring-danger',
      },
      size: {
        default: 'h-8 px-3 text-xs',
        sm: 'h-7 px-2.5 text-[11px]',
        lg: 'h-9 px-4 text-sm',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {}

export function Button({ className, variant, size, ...props }: ButtonProps) {
  return (
    <button className={cn(buttonVariants({ variant, size }), className)} {...props} />
  )
}
