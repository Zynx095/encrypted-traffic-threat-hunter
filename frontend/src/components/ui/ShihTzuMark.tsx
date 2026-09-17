import React from 'react'

export interface ShihTzuMarkProps {
  className?: string
  size?: number | string
  color?: string
}

export function ShihTzuMark({ className = '', size = 24, color = 'currentColor' }: ShihTzuMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 ${className}`}
      aria-label="ETTH Shadow Shih Tzu Brand Mark"
    >
      {/* Outer subtle halo/ring */}
      <circle cx="24" cy="24" r="22" stroke={color} strokeWidth="1.2" strokeOpacity="0.25" strokeDasharray="3 3" />
      
      {/* Shadow Shih Tzu Silhouette Profile */}
      <g fill={color}>
        {/* Head & Topknot Crown */}
        <path d="M 22 8 C 20 8 18 10 18 12 C 18 13.5 19 14.5 20.5 15 C 19 16 17 17.5 16 19.5 C 15 21.5 14.5 24 14 26 C 13.5 28 12.5 30 11 31.5 C 10 32.5 9 33 8 33.5 C 10 35 12.5 35.5 15 35 C 17.5 34.5 19 33 20 31.5 C 21 30 21.5 28 22 26 C 22.5 24 23.5 23 25 23 C 26.5 23 27.5 24 28 26 C 28.5 28 29 30 30 31.5 C 31 33 32.5 34.5 35 35 C 37.5 35.5 40 35 42 33.5 C 41 33 40 32.5 39 31.5 C 37.5 30 36.5 28 36 26 C 35.5 24 35 21.5 34 19.5 C 33 17.5 31 16 29.5 15 C 31 14.5 32 13.5 32 12 C 32 10 30 8 28 8 C 26 8 25 9.5 24 11 C 23 9.5 22 8 22 8 Z" opacity="0.9" />
        
        {/* Flowing Ear Silhouette Drops */}
        <path d="M 14 21 C 12 23 10 26 9.5 29 C 9 32 9.5 35 11 37 C 12.5 39 14.5 40 16 39.5 C 17.5 39 18 37 17.5 34.5 C 17 32 16 29 15.5 26 Z" opacity="0.75" />
        <path d="M 34 21 C 36 23 38 26 38.5 29 C 39 32 38.5 35 37 37 C 35.5 39 33.5 40 32 39.5 C 30.5 39 30 37 30.5 34.5 C 31 32 32 29 32.5 26 Z" opacity="0.75" />
        
        {/* Mysterious Muzzle & Nose Profile */}
        <path d="M 22 25 H 26 V 28 C 26 29.5 25 30.5 24 30.5 C 23 30.5 22 29.5 22 28 V 25 Z" opacity="0.95" />
        
        {/* Vigilant Shadow Eyes (Glowing subtle slits) */}
        <circle cx="20.5" cy="20.5" r="1.5" fill="#00ff41" opacity="0.9" />
        <circle cx="27.5" cy="20.5" r="1.5" fill="#00ff41" opacity="0.9" />
      </g>
    </svg>
  )
}
