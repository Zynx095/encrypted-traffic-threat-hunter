import { cn } from '../../lib/utils'
import { cva } from 'class-variance-authority'
import * as React from 'react'

const TabsContext = React.createContext<{
  value: string;
  onValueChange: (val: string) => void;
} | null>(null);

const tabsListVariants = cva(
  'inline-flex items-center justify-center rounded-sm bg-surface-800 p-1 text-etth-text/50',
  { variants: {} }
)

const tabsTriggerVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 py-1 text-sm font-medium ring-offset-surface-900 transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-etth-accent focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 data-[state=active]:bg-surface-700 data-[state=active]:text-etth-text data-[state=active]:shadow',
  { variants: {} }
)

export function Tabs({ className, defaultValue, ...props }: React.HTMLAttributes<HTMLDivElement> & { defaultValue?: string }) {
  const [value, setValue] = React.useState(defaultValue || '')
  return (
    <TabsContext.Provider value={{ value, onValueChange: setValue }}>
      <div className={cn('flex flex-col space-y-4', className)} {...props} />
    </TabsContext.Provider>
  )
}

export function TabsList({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn(tabsListVariants(), className)} {...props} />
}

export function TabsTrigger({ className, value, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { value?: string }) {
  const context = React.useContext(TabsContext)
  const active = context?.value === value
  return (
    <button
      className={cn(tabsTriggerVariants(), className)}
      data-state={active ? 'active' : 'inactive'}
      onClick={() => {
        if (value && context) context.onValueChange(value)
      }}
      {...props}
    />
  )
}

export function TabsContent({ className, value, ...props }: React.HTMLAttributes<HTMLDivElement> & { value?: string }) {
  const context = React.useContext(TabsContext)
  if (context?.value !== value) return null
  return <div className={cn('mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2', className)} {...props} />
}
