import { cn } from '../../lib/utils'
import { cva, type VariantProps } from 'class-variance-authority'


const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 px-4 py-2 rounded-sm font-medium text-sm transition-all duration-150 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-surface-900 disabled:opacity-50 disabled:pointer-events-none',
  {
    variants: {
      variant: {
        default: 'bg-etth-accent text-white hover:bg-etth-accent/90 focus:ring-etth-accent',
        secondary: 'bg-surface-600 text-etth-text border border-surface-500 hover:bg-surface-500 focus:ring-surface-500',
        ghost: 'text-etth-text/70 hover:bg-surface-700/50 hover:text-etth-text focus:ring-surface-500',
        outline: 'border border-surface-600 text-etth-text hover:bg-surface-700/50 focus:ring-surface-500',
      },
      size: {
        default: 'h-9 px-4 py-2',
        sm: 'h-8 px-3 text-xs',
        lg: 'h-10 px-8',
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
