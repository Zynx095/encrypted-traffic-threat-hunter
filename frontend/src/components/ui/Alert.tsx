import { cn } from '../../lib/utils'
import { cva, type VariantProps } from 'class-variance-authority'

const alertVariants = cva(
  'relative w-full rounded-sm border px-4 py-3 text-sm [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-etth-text [&>svg~*]:pl-7',
  {
    variants: {
      variant: {
        default: 'bg-surface-800 text-etth-text border-surface-700',
        destructive: 'border-danger/50 text-danger bg-danger/10',
        warning: 'border-warning/50 text-warning bg-warning/10',
        success: 'border-success/50 text-success bg-success/10',
        info: 'border-info/50 text-info bg-info/10',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
)

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof alertVariants> {}

export function Alert({ className, variant, ...props }: AlertProps) {
  return (
    <div className={cn(alertVariants({ variant }), className)} {...props} />
  )
}

export function AlertTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h5 className={cn('mb-1 font-medium leading-none tracking-tight', className)} {...props} />
  )
}

export function AlertDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return (
    <div className={cn('text-sm [&_p]:leading-relaxed text-etth-text/70', className)} {...props} />
  )
}
