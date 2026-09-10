import { useState } from 'react'
import { Outlet, NavLink, useLocation, Link } from 'react-router-dom'
import { NAVIGATION, NAV_GROUPS } from '../../lib/navigation'
import { cn } from '../../lib/utils'
import {
  LayoutDashboard,
  Search,
  Lock,
  Fingerprint,
  FlaskConical,
  Brain,
  Lightbulb,
  Database,
  FileText,
  Activity,
  AlertTriangle,
  Menu,
  X,
  Shield,
  ChevronRight,
} from 'lucide-react'

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  LayoutDashboard,
  Search,
  Lock,
  Fingerprint,
  FlaskConical,
  Brain,
  Lightbulb,
  Database,
  FileText,
}

export default function Layout() {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen bg-surface-900 flex">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* ── Sidebar ──────────────────────────────────────── */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-56 bg-surface-800 border-r border-surface-700 flex flex-col',
          'transition-transform duration-200 ease-in-out',
          'lg:relative lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Branding */}
        <div className="px-5 py-4 border-b border-surface-700">
          <Link to="/overview" className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-sm bg-accent/10 flex items-center justify-center border border-accent/20 group-hover:bg-accent/15 transition-colors">
              <Shield className="w-4 h-4 text-accent" />
            </div>
            <div>
              <h1 className="font-semibold text-etth-text text-sm tracking-wide">ETTH</h1>
              <p className="text-[10px] text-etth-text/40 leading-tight">Encrypted Traffic<br />Threat Hunter</p>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-3 px-3">
          {NAV_GROUPS.map((group) => {
            const groupRoutes = NAVIGATION.filter(
              (r) => r.group === group.id && !r.hidden
            )
            if (groupRoutes.length === 0) return null

            return (
              <div key={group.id} className="mb-4">
                <div className="px-3 mb-1.5">
                  <span className="text-[10px] font-medium uppercase tracking-widest text-etth-text/30">
                    {group.label}
                  </span>
                </div>
                <div className="space-y-0.5">
                  {groupRoutes.map((item) => {
                    const Icon = iconMap[item.icon] || Activity
                    const isActive =
                      location.pathname === item.path ||
                      (item.path !== '/overview' &&
                        location.pathname.startsWith(item.path))

                    return (
                      <NavLink
                        key={item.path}
                        to={item.path}
                        onClick={() => setSidebarOpen(false)}
                        className={cn(
                          'flex items-center gap-2.5 px-3 py-1.5 rounded-sm text-[13px] font-medium transition-all duration-150',
                          isActive
                            ? 'bg-accent/10 text-accent'
                            : 'text-etth-text/60 hover:bg-surface-700/40 hover:text-etth-text/90'
                        )}
                      >
                        <Icon className="w-4 h-4 shrink-0" />
                        <span>{item.label}</span>
                        {isActive && (
                          <div className="ml-auto w-1 h-1 rounded-full bg-accent" />
                        )}
                      </NavLink>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </nav>

        {/* Footer status */}
        <div className="px-4 py-3 border-t border-surface-700 space-y-1.5">
          <div className="flex items-center gap-2 text-[11px] text-etth-text/40">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-success" />
            </span>
            <span>Phase 6 Complete</span>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-warning/70">
            <AlertTriangle className="w-3 h-3" />
            <span>Pilot: Source-confounded</span>
          </div>
          <div className="text-[10px] text-etth-text/20 pt-1">
            ETTH v1.0.0
          </div>
        </div>
      </aside>

      {/* ── Main Content ─────────────────────────────────── */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-12 bg-surface-800/80 backdrop-blur-sm border-b border-surface-700 flex items-center justify-between px-4 lg:px-6 sticky top-0 z-30">
          <div className="flex items-center gap-3">
            {/* Mobile menu button */}
            <button
              className="lg:hidden p-1.5 rounded-sm text-etth-text/60 hover:text-etth-text hover:bg-surface-700/40 transition-colors"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              aria-label="Toggle navigation"
            >
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <Breadcrumb />
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-etth-text/30 font-mono">v1.0.0</span>
          </div>
        </header>

        {/* Page content */}
        <div className="flex-1 overflow-auto">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

// ── Breadcrumb ──────────────────────────────────────────────

function Breadcrumb() {
  const location = useLocation()
  const pathnames = location.pathname.split('/').filter(Boolean)

  if (pathnames.length === 0) return null

  // Map path segments to readable labels
  const segmentLabel = (segment: string) => {
    const route = NAVIGATION.find((r) => r.path === `/${segment}`)
    if (route) return route.label
    return segment.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
  }

  return (
    <nav className="flex items-center gap-1.5 text-[13px]" aria-label="Breadcrumb">
      <Link
        to="/overview"
        className="text-etth-text/40 hover:text-etth-text/70 transition-colors"
      >
        ETTH
      </Link>
      {pathnames.map((segment, index) => {
        const routeTo = `/${pathnames.slice(0, index + 1).join('/')}`
        const isLast = index === pathnames.length - 1

        return (
          <span key={segment} className="flex items-center gap-1.5">
            <ChevronRight className="w-3 h-3 text-etth-text/20" />
            {isLast ? (
              <span className="text-etth-text/80 font-medium">
                {segmentLabel(segment)}
              </span>
            ) : (
              <Link
                to={routeTo}
                className="text-etth-text/40 hover:text-etth-text/70 transition-colors"
              >
                {segmentLabel(segment)}
              </Link>
            )}
          </span>
        )
      })}
    </nav>
  )
}
