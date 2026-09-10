import type { LucideIcon } from 'lucide-react'

export interface RouteConfig {
  path: string
  label: string
  icon: string
  group: string
  description?: string
  hidden?: boolean
}

export const NAV_GROUPS = [
  { id: 'command', label: 'Console' },
  { id: 'tls', label: 'Intelligence' },
  { id: 'research', label: 'Analytics' },
] as const

export type NavGroupId = typeof NAV_GROUPS[number]['id']

export const NAVIGATION: RouteConfig[] = [
  { path: '/overview',     label: 'Dashboard',         icon: 'LayoutDashboard', group: 'command' },
  { path: '/threat-hunt',  label: 'Threat Hunt',       icon: 'Search',          group: 'command' },
  { path: '/live',         label: 'Live Stream',       icon: 'Radio',           group: 'command' },

  { path: '/tls',          label: 'TLS Analysis',      icon: 'Lock',            group: 'tls' },
  { path: '/fingerprints', label: 'Fingerprints',      icon: 'Fingerprint',     group: 'tls' },

  { path: '/experiments',    label: 'Experiments',      icon: 'FlaskConical',   group: 'research' },
  { path: '/models',         label: 'Models',           icon: 'Brain',          group: 'research' },
  { path: '/explainability', label: 'Explainability',   icon: 'Lightbulb',      group: 'research' },
  { path: '/datasets',       label: 'Datasets',         icon: 'Database',       group: 'research' },
  { path: '/research',       label: 'Research',         icon: 'FileText',       group: 'research' },
] as const