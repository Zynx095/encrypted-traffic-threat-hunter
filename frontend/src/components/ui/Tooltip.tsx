import { cn } from '../../lib/utils'

export function Tooltip({ children, content, side = 'top' }: { children: React.ReactNode; content: string; side?: 'top' | 'bottom' | 'left' | 'right' }) {
  return (
    <div className="group relative inline-block">
      {children}
      <div className={cn(
        'invisible absolute z-50 px-2 py-1 text-xs text-white bg-surface-900 rounded opacity-0 group-hover:visible group-hover:opacity-100 transition-all duration-200',
        side === 'top' && 'bottom-full left-1/2 -translate-x-1/2 mb-2',
        side === 'bottom' && 'top-full left-1/2 -translate-x-1/2 mt-2',
        side === 'left' && 'right-full top-1/2 -translate-y-1/2 mr-2',
        side === 'right' && 'left-full top-1/2 -translate-y-1/2 ml-2',
      )}>
        {content}
        <div className={cn(
          'absolute w-2 h-2 bg-surface-900 rotate-45',
          side === 'top' && '-bottom-1 left-1/2 -translate-x-1/2',
          side === 'bottom' && '-top-1 left-1/2 -translate-x-1/2',
          side === 'left' && '-right-1 top-1/2 -translate-y-1/2',
          side === 'right' && '-left-1 top-1/2 -translate-y-1/2',
        )} />
      </div>
    </div>
  )
}
