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
  Target,
  Radio,
  Menu,
  X,
  ChevronRight,
} from 'lucide-react'
import { ShihTzuMark } from '../ui/ShihTzuMark'

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
  Target,
  Radio,
  Activity,
}

export default function Layout() {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen bg-surface-900 flex font-sans">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-52 bg-surface-800 border-r border-surface-700 flex flex-col',
          'lg:relative lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Shadow Shih Tzu Brand Header */}
        <div className="px-3.5 py-3 border-b border-surface-700 bg-surface-900/40">
          <Link to="/targets" className="flex items-center gap-2.5 group">
            <ShihTzuMark size={24} className="text-accent group-hover:text-accent/90 transition-colors" />
            <div className="min-w-0">
              <span className="font-semibold text-xs text-etth-text tracking-wider uppercase block">ETTH</span>
              <span className="text-[9px] font-mono text-etth-text/40 block truncate">Encrypted Threat Hunter</span>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-2 px-2">
          {NAV_GROUPS.map((group) => {
            const groupRoutes = NAVIGATION.filter(
              (r) => r.group === group.id && !r.hidden
            )
            if (groupRoutes.length === 0) return null

            return (
              <div key={group.id} className="mb-3">
                <div className="px-2 mb-1">
                  <span className="text-[10px] font-medium uppercase tracking-widest text-etth-text/25">
                    {group.label}
                  </span>
                </div>
                <div className="space-y-px">
                  {groupRoutes.map((item) => {
                    const Icon = iconMap[item.icon] || Activity
                    const isActive =
                      location.pathname === item.path ||
                      (item.path !== '/' &&
                        location.pathname.startsWith(item.path))

                    return (
                      <NavLink
                        key={item.path}
                        to={item.path}
                        onClick={() => setSidebarOpen(false)}
                        className={cn(
                          'flex items-center gap-2 px-2 py-1.5 rounded-sm text-[12px] transition-colors',
                          isActive
                            ? 'bg-surface-700 text-etth-text font-medium'
                            : 'text-etth-text/50 hover:bg-surface-700/40 hover:text-etth-text/80'
                        )}
                      >
                        <Icon className="w-3.5 h-3.5 shrink-0" />
                        <span>{item.label}</span>
                      </NavLink>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </nav>

        {/* Footer */}
        <div className="px-3 py-2 border-t border-surface-700">
          <div className="flex items-center gap-1.5 text-[10px] text-etth-text/25">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-success/70" />
            <span>Phase 6 · Pilot</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-10 bg-surface-800 border-b border-surface-700 flex items-center justify-between px-4 lg:px-5 sticky top-0 z-30">
          <div className="flex items-center gap-2">
            <button
              className="lg:hidden p-1 rounded-sm text-etth-text/50 hover:text-etth-text hover:bg-surface-700/40 transition-colors"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              aria-label="Toggle navigation"
            >
              {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
            </button>
            <Breadcrumb />
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

function Breadcrumb() {
  const location = useLocation()
  const pathnames = location.pathname.split('/').filter(Boolean)

  if (pathnames.length === 0) return null

  const segmentLabel = (segment: string) => {
    const route = NAVIGATION.find((r) => r.path === `/${segment}`)
    if (route) return route.label
    return segment.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
  }

  return (
    <nav className="flex items-center gap-1 text-[12px]" aria-label="Breadcrumb">
      <Link
        to="/targets"
        className="text-etth-text/30 hover:text-etth-text/60 transition-colors"
      >
        ETTH
      </Link>
      {pathnames.map((segment, index) => {
        const routeTo = `/${pathnames.slice(0, index + 1).join('/')}`
        const isLast = index === pathnames.length - 1

        return (
          <span key={segment} className="flex items-center gap-1">
            <ChevronRight className="w-3 h-3 text-etth-text/15" />
            {isLast ? (
              <span className="text-etth-text/60">
                {segmentLabel(segment)}
              </span>
            ) : (
              <Link
                to={routeTo}
                className="text-etth-text/30 hover:text-etth-text/60 transition-colors"
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
