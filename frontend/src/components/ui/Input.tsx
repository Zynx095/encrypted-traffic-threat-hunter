import { cn } from '../../lib/utils'

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

export function Input({ className, ...props }: InputProps) {
  return (
    <input
      className={cn(
        'flex h-9 w-full rounded-sm border border-surface-600 bg-surface-800 px-3 py-1 text-sm text-etth-text placeholder:text-etth-text/40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-etth-accent disabled:cursor-not-allowed disabled:opacity-50',
        className
      )}
      {...props}
    />
  )
}

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {}

export function Textarea({ className, ...props }: TextareaProps) {
  return (
    <textarea
      className={cn(
        'flex min-h-[80px] w-full rounded-sm border border-surface-600 bg-surface-800 px-3 py-2 text-sm text-etth-text placeholder:text-etth-text/40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-etth-accent disabled:cursor-not-allowed disabled:opacity-50',
        className
      )}
      {...props}
    />
  )
}
