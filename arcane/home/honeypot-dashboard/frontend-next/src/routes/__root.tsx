// Root document of the modernization port (#1608). Design contract: the
// markup speaks the exact class vocabulary of Xore/theme's theme.css (the
// same vendored stylesheet the Go dashboard serves), so the port inherits
// the claude-pure element set 1:1 — no visual drift by construction.
import { useEffect } from 'react'
import '../index.css'
import { HeadContent, Scripts, createRootRoute, Link, redirect, useRouterState } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { AppShell } from '../components/AppShell'
import { Card, CardDescription, CardTitle } from '../components/ui/card'
import { APP_CONFIG } from '../config/app-config'
import { getSessionUser, type User } from '../lib/auth'
import { activeBanner, type BannerView, type BehaviorConfig, type PresentationConfig } from '../lib/banner'
import { pullAppearance } from '../lib/prefs'
import { useSessionWatch } from '../lib/useSessionWatch'
import { type Appearance } from '../lib/appearanceCookie'
// Inlined by Vite from vite.config.ts. Nitro's dev middleware treats unknown
// root-level extensions as application routes, so importing theme.lock?raw
// directly works in builds but returns the app's 404 response in development.
const themeLock = import.meta.env.VITE_THEME_LOCK

type ShellConfig = {
  banner: BannerView | null
  showProblemReportButton: boolean
  appName: string
  /** #2178: true when /api/v1/config could not be read. The shell then
   * fails conservative — banner slot says the truth about what is unknown,
   * and the report-a-problem affordance stays up — instead of rendering
   * "no banner, no button", which was indistinguishable from a deliberately
   * quiet deployment precisely when the operator most needs both. */
  configFailed?: boolean
}

// One /api/v1/config read backs every shell-wide (not per-route) piece of
// chrome: the banner and whether the "Report a problem" button shows at
// all (behavior.show_problem_report_button) — fetched together so neither
// costs its own round trip.
const fetchShellConfig = createServerFn({ method: 'GET' }).handler(async (): Promise<ShellConfig> => {
  const { serviceJSONResult } = await import('../lib/backend.server')
  const result = await serviceJSONResult<{
    payload?: {
      presentation?: (PresentationConfig & { app_name?: string })
      behavior?: BehaviorConfig & { show_problem_report_button?: boolean }
    }
  }>('/api/v1/config')
  if (!result.ok) {
    // #2178: serviceJSON collapsed this failure into an all-defaults shell.
    // A configured incident/maintenance banner went invisible and the one
    // button for telling an operator something was wrong disappeared with
    // it. The fallback banner is honest about being a fallback rather than
    // inventing maintenance state; the actual configured banner (if any)
    // simply cannot be known from here.
    return {
      banner: {
        text: 'Dashboard configuration could not be loaded — banners and feature switches may be out of date.',
        severity: 'warning',
      },
      showProblemReportButton: true,
      appName: APP_CONFIG.name,
      configFailed: true,
    }
  }
  const config = result.body
  return {
    banner: activeBanner(config?.payload?.presentation, config?.payload?.behavior),
    showProblemReportButton: config?.payload?.behavior?.show_problem_report_button ?? false,
    // Operator-editable brand (settings → Application name) — feeds the
    // per-navigation document titles (#1653: every Go page titled
    // "{brandText} — page").
    appName: config?.payload?.presentation?.app_name || APP_CONFIG.name,
  }
})

// #1833: the appearance the server can know before it renders anything.
//
// __root rendered a bare <html lang="en"> and let an inline script mutate
// document.documentElement afterwards. That works only because React does
// not strip attributes it did not render, and it cannot avoid the flash:
// on a device that has never run this dashboard there is no localStorage
// to read, so the first frame paints the default ground and repaints once
// pullAppearance() resolves. A theme owns the ground, the sidebar, every
// surface and the whole text ramp, so that is a full-page flash on the
// machine where the operator has the least context for what it should
// look like.
//
// The cookie is a first-paint hint and nothing more. localStorage and the
// server preference remain the source of truth, so cookies being blocked
// degrades to exactly the previous behaviour rather than to a wrong one.
const getAppearance = createServerFn({ method: 'GET' }).handler(async (): Promise<Appearance> => {
  const { getRequest } = await import('@tanstack/react-start/server')
  const { readAppearanceCookie } = await import('../lib/appearanceCookie')
  try {
    return readAppearanceCookie(getRequest().headers.get('cookie'))
  } catch {
    return { mode: null, theme: null }
  }
})

// #1828: an optional stylesheet layered after theme.css, for the design
// lab's variants. Read once at module scope -- it is a property of the
// process, not of a request, and production never sets it.
const variantCSS = process.env.VARIANT_CSS ?? ''

// #2143: theme.css used to be linked bare, so a re-vendor changed bytes at an
// unchanged URL and shipped behind exactly the stale cache #1852 recorded.
// Key the URL by the stylesheet's sha256 as pinned in theme.lock: the same
// hash sync-theme.sh writes is what check-vendored-theme.sh enforces against
// public/static/theme.css, so the version key tracks the bytes actually
// served -- identical upstream content keeps its URL (cacheable between
// deploys), any re-vendor rotates it. Short prefix is enough for a cache key;
// commit is the fallback field so an unparsable lock degrades to the
// historical bare link rather than emitting one with an empty query.
const lockValue = (key: string) => new RegExp(`^${key}=([0-9a-f]+)$`, 'm').exec(themeLock)?.[1] ?? ''
const themeCSSVersion = (lockValue('sha256') || lockValue('commit')).slice(0, 12)
const themeCSSHref = themeCSSVersion ? `/static/theme.css?v=${themeCSSVersion}` : '/static/theme.css'

export const Route = createRootRoute({
  // BFF-owned auth: every navigation resolves the redis session on the
  // server; unauthenticated requests bounce to the Keycloak flow. The
  // /auth/* server routes stay reachable, and the resolved user rides the
  // router context for the shell (avatar, profile).
  beforeLoad: async ({ location }) => {
    if (location.pathname.startsWith('/auth/')) return {}
    const user = await getSessionUser()
    if (!user) {
      throw redirect({
        href: `/auth/login?return_to=${encodeURIComponent(location.pathname + location.searchStr)}`,
      })
    }
    return { user }
  },
  // Shell-wide chrome (banner, problem-report button) is fetched once here
  // rather than per-route, both because every page shares it and so
  // /auth/* skips the extra backend round-trip pre-login.
  loader: async ({ location }): Promise<ShellConfig & { appearance: Appearance }> => {
    // Signed-out pages get the appearance too: /auth/login renders before
    // there is a session, and defaulting it there is the one flash an
    // operator sees on every new device.
    const appearance = await getAppearance()
    if (location.pathname.startsWith('/auth/')) {
      return { banner: null, showProblemReportButton: false, appName: APP_CONFIG.name, appearance }
    }
    return { ...(await fetchShellConfig()), appearance }
  },
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { name: 'robots', content: 'noindex, nofollow' },
      { title: APP_CONFIG.meta.title },
    ],
    links: [
      { rel: 'stylesheet', href: themeCSSHref },
      // #1828: a design-lab variant layers its token overrides on the
      // vendored stylesheet instead of replacing it, so a variant is a diff
      // against what ships rather than a fork of it — the authoring pattern
      // branding/design-lab/v5-picks-override.css already documents.
      //
      // Absent unless VARIANT_CSS names one, so production renders exactly
      // one stylesheet and this costs nothing.
      ...(variantCSS ? [{ rel: 'stylesheet' as const, href: variantCSS }] : []),
    ],
    scripts: [
      {
        // Pre-paint theme + palette boot, byte-compatible with the Go
        // dashboard's bootstrap: same localStorage keys (hp-theme,
        // hp-palette), same data attributes — an operator switching between
        // tiers during the transition keeps their appearance.
        //
        // Two orthogonal axes, which is easy to misread from the key names:
        //   hp-theme   -> data-theme      the light/dark mode; absent = system
        //   hp-palette -> data-hp-theme   the named theme (claude, slate, …)
        //
        // #1754: this script no longer deletes anything. It used to remove
        // any hp-theme it did not recognise and any hp-palette that failed
        // its shape check, which meant an operator's stored choice was
        // destroyed on first paint, before a line of React ran and with
        // nothing else on the page holding a copy. A value this script
        // cannot use is simply not applied; the page falls back to default
        // tokens and the choice survives to be read by something that can.
        //
        // The shape check matches the server's rule for the same field
        // (preferences.rs::theme_name) so a name cannot be accepted by one
        // end and rejected by the other. It is deliberately a shape and not
        // a list of the nine themes we ship today: a theme is CSS in the
        // vendored stylesheet, so a new one must work the moment it is
        // vendored, without a matching frontend deploy.
        //
        // Both data-hp-theme and data-hp-palette are set. Upstream treats
        // the first as canonical and the second as an alias; this repo still
        // reads dataset.hpPalette in settings.tsx.
        children:
          '(function(){try{var d=document.documentElement;var t=localStorage.getItem("hp-theme");if(t==="light"||t==="dark"){d.dataset.theme=t;}d.classList.toggle("dark",t==="dark"||(!t&&matchMedia("(prefers-color-scheme: dark)").matches));var p=localStorage.getItem("hp-palette");if(p&&/^[a-z][a-z0-9-]{2,31}$/.test(p)){d.dataset.hpTheme=p;d.dataset.hpPalette=p;}}catch(e){}})();',
      },
    ],
  }),
  shellComponent: RootDocument,
  // #1575's "humane 404" (notfound.html): this dashboard's own empty-state
  // voice — icon, muted hint, one surface-pill action — given to the 404,
  // instead of a bare heading.
  notFoundComponent: () => (
    <Card className="grid min-h-[56vh] place-items-center px-5 py-6 text-center" role="status">
      <div>
        <div className="text-muted-foreground opacity-60 [&_svg]:size-[26px]" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10" />
            <polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76" />
          </svg>
        </div>
        <CardTitle className="heading-serif mb-0.5 mt-2 text-[17px] font-medium"><h1>Page not found</h1></CardTitle>
        <CardDescription className="mx-auto max-w-[420px] text-[12.5px]">
          Whatever you were looking for isn't at this address — check the link, or head back to a page that exists.
        </CardDescription>
        <Link className="empty-state__action" to="/">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
          </svg>
          Go back home
        </Link>
      </div>
    </Card>
  ),
})

// #1755: reconcile this device against the operator's stored appearance once
// per session.
//
// This used to live in settings.tsx's mount effect, which meant a new device,
// a new browser profile or cleared storage showed the *default* appearance on
// every page until the operator happened to open Settings. With accent-only
// palettes that was a wrong button colour. Now that a theme owns the ground
// and the whole text ramp, it is the entire dashboard in the wrong theme.
//
// Root mount rather than per-route: the pull is one request and the answer
// does not change while the tab is open, so doing it per navigation would be
// a request per page for a value that cannot have moved.
//
// Deliberately not an SSR-time render decision. The server has the session
// and could emit the attributes on <html> directly, which would also remove
// the flash on a cold load -- that needs a cookie, because there is none in
// this stack today and localStorage is per-device by definition. Tracked as
// the remaining part of #1755 rather than smuggled in here.
function useStoredAppearance(enabled: boolean) {
  useEffect(() => {
    if (enabled) void pullAppearance()
  }, [enabled])
}

function RootDocument({ children }: { children: React.ReactNode }) {
  const isAuthRoute = useRouterState({ select: (state) => state.location.pathname.startsWith('/auth/') })
  const { banner, showProblemReportButton, appName, appearance } = Route.useLoaderData()
  // beforeLoad already resolved the session user into router context for
  // every non-/auth navigation — thread it to the shell so the sidebar
  // profile widget and topbar avatar show a real identity (#1653).
  const { user } = Route.useRouteContext() as { user?: User | null }
  useStoredAppearance(!isAuthRoute)
  // #1975: a tab that sat hidden long enough for its session to die finds
  // out the moment it comes back, not the next time the operator clicks
  // something and gets an unexplained failure. Root-mounted because it has
  // to outlive every navigation; it no-ops on /auth/* itself.
  useSessionWatch()
  return (
    // #1833: rendered, not scripted. Viewing source now shows the
    // operator's theme on <html> rather than only a script that will set
    // it. The boot script below stays as the fallback for a first visit
    // with no cookie yet, and for a device where cookies are blocked.
    <html
      lang="en"
      suppressHydrationWarning
      className={appearance?.mode === 'dark' ? 'dark' : undefined}
      {...(appearance?.mode ? { 'data-theme': appearance.mode } : {})}
      {...(appearance?.theme ? { 'data-hp-theme': appearance.theme, 'data-hp-palette': appearance.theme } : {})}
    >
      <head>
        <HeadContent />
      </head>
      <body>
        {isAuthRoute ? children : <AppShell banner={banner} showProblemReportButton={showProblemReportButton} user={user ?? null} appName={appName}>
          {children}
        </AppShell>}
        <Scripts />
      </body>
    </html>
  )
}
