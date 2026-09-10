/**
 * ETTH Design Constants
 *
 * Centralized constants for chart theming and UI configuration.
 * Chart colors mirror the CSS variable values since Recharts
 * requires concrete color strings for SVG fill/stroke attributes.
 *
 * If you change the CSS variables in index.css, update these
 * constants to match.
 */

// ── Chart Colors ────────────────────────────────────────────

export const CHART_COLORS = {
  /** Accent/threat — malicious indicators */
  accent:  '#E94560',
  /** Informational — neutral data */
  info:    '#3B82F6',
  /** Benign/safe — success indicators */
  success: '#10B981',
  /** Warning — caution indicators */
  warning: '#F59E0B',
  /** Neutral — secondary data series */
  neutral: '#64748B',
  /** Danger — critical/error */
  danger:  '#EF4444',
} as const

/** Ordered palette for multi-series charts */
export const CHART_PALETTE = [
  CHART_COLORS.accent,
  CHART_COLORS.info,
  CHART_COLORS.success,
  CHART_COLORS.warning,
  CHART_COLORS.neutral,
] as const

// ── Recharts Theme ──────────────────────────────────────────

export const RECHARTS_TOOLTIP = {
  contentStyle: {
    backgroundColor: 'rgb(14, 17, 23)',
    border: '1px solid rgb(26, 30, 39)',
    borderRadius: '8px',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)',
    fontSize: '12px',
  },
  labelStyle: {
    color: 'rgb(226, 232, 240)',
    fontWeight: 500,
    marginBottom: '4px',
  },
  itemStyle: {
    color: 'rgb(148, 163, 184)',
    fontSize: '12px',
  },
} as const

export const RECHARTS_GRID = {
  stroke: 'rgb(26, 30, 39)',
  strokeDasharray: '3 3',
} as const

export const RECHARTS_AXIS = {
  stroke: 'rgb(59, 67, 84)',
  tick: { fill: 'rgb(100, 116, 139)', fontSize: 11 },
} as const

// ── Transitions ─────────────────────────────────────────────

export const TRANSITION = {
  fast: 'all 120ms ease',
  default: 'all 150ms ease',
  slow: 'all 220ms ease',
} as const

// ── Experiment Definitions ──────────────────────────────────
// Shared labels for experiment IDs across pages

export const EXPERIMENT_LABELS: Record<string, string> = {
  A: 'Flow-only',
  B: 'JA3-only',
  C: 'JA4-only',
  D: 'JA3 + Flow',
  E: 'JA4 + Flow',
}

export const EXPERIMENT_DESCRIPTIONS: Record<string, string> = {
  A: 'Behavioral flow features without fingerprints',
  B: 'JA3 fingerprint features only',
  C: 'JA4 fingerprint features only',
  D: 'JA3 fingerprints combined with flow features',
  E: 'JA4 fingerprints combined with flow features',
}
