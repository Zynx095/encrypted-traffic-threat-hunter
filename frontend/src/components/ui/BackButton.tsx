import React from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'

export interface BackButtonProps {
  label?: string
  to?: string
  className?: string
}

export function BackButton({ label = 'OVERVIEW', to = '/targets', className = '' }: BackButtonProps) {
  const navigate = useNavigate()

  return (
    <button
      onClick={() => navigate(to)}
      className={`back-btn ${className}`}
      aria-label={`Back to ${label}`}
    >
      <ArrowLeft />
      <span>{label}</span>
    </button>
  )
}
