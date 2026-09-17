export interface RouteConfig {
  path: string
  label: string
  icon: string
  group: string
  description?: string
  hidden?: boolean
}

export const NAV_GROUPS = [
  { id: 'operate', label: 'OPERATE' },
  { id: 'investigate', label: 'INVESTIGATE' },
  { id: 'research', label: 'RESEARCH' },
] as const

export type NavGroupId = typeof NAV_GROUPS[number]['id']

export const NAVIGATION: RouteConfig[] = [
  // OPERATE
  { path: '/targets',      label: 'Targets',           icon: 'Target',          group: 'operate' },
  { path: '/live',         label: 'Monitor',           icon: 'Radio',           group: 'operate' },
  { path: '/sessions',     label: 'Sessions',          icon: 'Activity',        group: 'operate' },

  // INVESTIGATE
  { path: '/threat-hunt',  label: 'Threat Hunt',       icon: 'Search',          group: 'investigate' },
  { path: '/flows',        label: 'Flows',             icon: 'Activity',        group: 'investigate' },
  { path: '/tls',          label: 'TLS',               icon: 'Lock',            group: 'investigate' },
  { path: '/fingerprints', label: 'Fingerprints',      icon: 'Fingerprint',     group: 'investigate' },

  // RESEARCH
  { path: '/experiments',    label: 'Experiments',      icon: 'FlaskConical',   group: 'research' },
  { path: '/models',         label: 'Models',           icon: 'Brain',          group: 'research' },
  { path: '/explainability', label: 'Explainability',   icon: 'Lightbulb',      group: 'research' },
  { path: '/datasets',       label: 'Datasets',         icon: 'Database',       group: 'research' },
  { path: '/research',       label: 'Research',         icon: 'FileText',       group: 'research' },
] as const