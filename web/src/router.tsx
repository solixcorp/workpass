import { QueryClient } from '@tanstack/react-query'
import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  Outlet,
  redirect,
} from '@tanstack/react-router'
import { AppShell } from '@/components/app-shell'
import { enrollmentQuery } from '@/lib/mfa'
import { GroupsPage } from '@/features/admin/groups-page'
import { LoadingScreen } from '@/components/loading-screen'
import { AccessRequestsAdminPage } from '@/features/admin/access-requests-page'
import { AccountsAdminPage } from '@/features/admin/accounts-admin-page'
import { AccountsPage } from '@/features/accounts/accounts-page'
import { ApplicationsPage } from '@/features/admin/applications-page'
import { ApplicationPage } from '@/features/admin/integration/application-page'
import { IntegrationWizardPage } from '@/features/admin/integration/integration-wizard-page'
import { ReportsPage } from '@/features/admin/reports-page'
import { ActivityPage } from '@/features/me/activity-page'
import { MyAccountPage } from '@/features/me/my-account-page'
import { UserDetailPage } from '@/features/admin/user-detail-page'
import { NewIntegrationPage } from '@/features/admin/integration/new-integration-page'
import { AuditPage } from '@/features/admin/audit-page'
import { PoliciesPage } from '@/features/admin/policies-page'
import { SettingsPage } from '@/features/admin/settings-page'
import { AdminOverviewPage } from '@/features/admin/overview-page'
import { UsersPage } from '@/features/admin/users-page'
import { ActivationPage } from '@/features/auth/activation-page'
import { LoginPage } from '@/features/auth/login-page'
import { PortalHomePage } from '@/features/portal/home-page'
import { RequestsPage } from '@/features/requests/requests-page'
import { SecurityPage } from '@/features/security/security-page'
import { isAdministrator } from '@/lib/auth-client'
import {
  AUTHORIZE_PATH,
  authorizeSearchFromSignedQuery,
  recallSignedQuery,
  rememberSignedQuery,
} from '@/lib/authorize-url'
import { sessionQuery } from '@/lib/queries'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
})

type RouterContext = { queryClient: QueryClient }

const rootRoute = createRootRouteWithContext<RouterContext>()({
  component: Outlet,
})

function safeRedirect(value: unknown): string | undefined {
  // Only same-origin, in-app paths: never an absolute or protocol-relative URL.
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//')
    ? value
    : undefined
}

/**
 * Leave the SPA for the fixed WorkPass OAuth2 flow. A same-origin `href` redirect
 * would be treated as an in-app route, so this is a real document navigation;
 * the never-settling promise keeps the loading screen up until the browser leaves.
 */
function startWorkpassLogin(returnTo: string | undefined): Promise<never> {
  window.location.replace(workpassLoginUrl(returnTo))
  return new Promise<never>(() => undefined)
}

function workpassLoginUrl(returnTo: string | undefined): string {
  const target = new URL('/auth/login', window.location.origin)
  const safe = safeRedirect(returnTo)
  if (safe && safe !== '/') target.searchParams.set('redirect', safe)
  return target.toString()
}

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  validateSearch: (
    search: Record<string, unknown>,
  ): { redirect?: string; oq?: string; error?: string } => {
    const target = safeRedirect(search.redirect)
    // `oq` is the signed OIDC request handed over by /sign-in; the backend
    // re-verifies its signature when it is resumed, so it is passed through.
    const oq = typeof search.oq === 'string' && search.oq.length <= 16384 ? search.oq : undefined
    return {
      ...(target ? { redirect: target } : {}),
      ...(oq ? { oq } : {}),
      ...(search.error === 'oauth' ? { error: 'oauth' } : {}),
    }
  },
  beforeLoad: async ({ search }) => {
    // The sign-in screen only exists inside an authorization request. A bare
    // visit starts the fixed WorkPass OAuth2 flow, which comes back here
    // with the signed request attached.
    if (!search.oq) await startWorkpassLogin(search.redirect)
  },
  pendingComponent: LoadingScreen,
  component: LoginPage,
})

const activateRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/activate',
  component: ActivationPage,
})

const authenticatedRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'authenticated',
  beforeLoad: async ({ context, location }) => {
    const session = await context.queryClient.ensureQueryData(sessionQuery)
    if (!session) await startWorkpassLogin(location.href)
    // A required second factor that is not set up yet sends the user to the
    // enrollment screen; the server decides, the client only follows.
    if (location.pathname !== '/security') {
      const enrollment = await context.queryClient.fetchQuery({ ...enrollmentQuery, staleTime: 15_000 }).catch(() => null)
      if (enrollment?.mustEnroll) throw redirect({ to: '/security' })
    }
    return { session }
  },
  component: AppShell,
})

const homeRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/',
  component: PortalHomePage,
})

const securityRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/security',
  component: SecurityPage,
})

const accountsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/accounts',
  component: AccountsPage,
})

const requestsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/requests',
  component: RequestsPage,
})

// Administrator screens are hidden for non-admins as a convenience only; every
// /api/admin/* call is still authorized by the backend's requireAdministrator.
const myAccountRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/me',
  component: MyAccountPage,
})

const activityRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/activity',
  component: ActivityPage,
})

const adminRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin',
  beforeLoad: ({ context }) => {
    if (!isAdministrator(context.session)) throw redirect({ to: '/' })
  },
  component: Outlet,
})

const adminIndexRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/',
  component: AdminOverviewPage,
})

const adminUsersRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/users',
  component: UsersPage,
})

const adminUserRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/users/$id',
  component: UserDetailPage,
})

const adminReportsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/reports',
  component: ReportsPage,
})

const adminGroupsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/groups',
  component: GroupsPage,
})

const adminRequestsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/access-requests',
  component: AccessRequestsAdminPage,
})

const adminAccountsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/accounts',
  component: AccountsAdminPage,
})

const adminApplicationsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/applications',
  component: ApplicationsPage,
})

const adminNewApplicationRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/applications/new',
  validateSearch: (search: Record<string, unknown>): { method?: string; type?: string } => ({
    ...(typeof search.method === 'string' ? { method: search.method } : {}),
    ...(typeof search.type === 'string' ? { type: search.type } : {}),
  }),
  component: NewIntegrationPage,
})

const adminWizardRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/applications/wizard',
  component: IntegrationWizardPage,
})

const adminApplicationRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/applications/$slug',
  component: ApplicationPage,
})

const adminPoliciesRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/policies',
  component: PoliciesPage,
})

const adminSettingsRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/settings',
  component: SettingsPage,
})

const adminAuditRoute = createRoute({
  getParentRoute: () => adminRoute,
  path: '/audit',
  component: AuditPage,
})

const routeTree = rootRoute.addChildren([
  loginRoute,
  activateRoute,
  authenticatedRoute.addChildren([
    homeRoute,
    securityRoute,
    myAccountRoute,
    activityRoute,
    requestsRoute,
    accountsRoute,
    adminRoute.addChildren([
      adminIndexRoute,
      adminUsersRoute,
      adminUserRoute,
      adminReportsRoute,
      adminGroupsRoute,
      adminAccountsRoute,
      adminApplicationsRoute,
      adminNewApplicationRoute,
      adminWizardRoute,
      adminApplicationRoute,
      adminRequestsRoute,
      adminAuditRoute,
      adminPoliciesRoute,
      adminSettingsRoute,
    ]),
  ]),
])

export const router = createRouter({
  routeTree,
  rewrite: {
    // What the address bar shows while the sign-in screen is open.
    output: ({ url }) => {
      if (url.pathname !== '/login') return undefined
      const oq = url.searchParams.get('oq')
      const search = oq ? authorizeSearchFromSignedQuery(oq) : null
      if (!oq || !search) return undefined
      rememberSignedQuery(search, oq)
      url.pathname = AUTHORIZE_PATH
      url.search = search
      return url
    },
    // The router reads its own address back. Give it the signed request that
    // address stands for; a hard reload never gets here, it goes to the server
    // and comes back with a fresh one.
    input: ({ url }) => {
      if (url.pathname !== AUTHORIZE_PATH) return undefined
      const oq = recallSignedQuery(url.search)
      url.pathname = '/login'
      url.search = oq ? `?oq=${encodeURIComponent(oq)}` : ''
      return url
    },
  },
  context: { queryClient },
  defaultPreload: 'intent',
  defaultPendingMs: 120,
  defaultPendingMinMs: 700,
  defaultPendingComponent: LoadingScreen,
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
