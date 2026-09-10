import React, { useState } from 'react'
import { Copy, Check } from 'lucide-react'
import { cn } from '../../lib/utils'
import { Tooltip } from './Tooltip'

export interface CodeValueProps {
  value: string
  copyable?: boolean
  truncate?: boolean
  maxLength?: number
  className?: string
}

export function CodeValue({ value, copyable = false, truncate = false, maxLength = 20, className }: CodeValueProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const displayValue = truncate && value.length > maxLength 
    ? `${value.substring(0, maxLength)}...` 
    : value

  const content = (
    <span className={cn('inline-flex items-center gap-1.5 font-mono text-sm bg-surface-700/50 rounded px-1.5 py-0.5 text-etth-text group', className)}>
      <span>{displayValue}</span>
      {copyable && (
        <button
          onClick={handleCopy}
          className="opacity-0 group-hover:opacity-100 transition-opacity focus:opacity-100 focus:outline-none"
          title="Copy to clipboard"
        >
          {copied ? (
            <Check className="w-3.5 h-3.5 text-success" />
          ) : (
            <Copy className="w-3.5 h-3.5 text-etth-text/50 hover:text-etth-text transition-colors" />
          )}
        </button>
      )}
    </span>
  )

  if (truncate && value.length > maxLength) {
    return (
      <Tooltip content={value}>
        {content}
      </Tooltip>
    )
  }

  return content
}
