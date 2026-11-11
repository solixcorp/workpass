import { queryOptions } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

/** How an app signs users in. `api` is an OAuth client with no user (machine to machine). */
export type Method = 'oidc' | 'saml' | 'wsfed' | 'swa' | 'api' | 'bookmark'
export type ClientType = 'web' | 'spa' | 'native' | 'service'
export type GrantKey = 'authorization_code' | 'refresh_token' | 'client_credentials' | 'device_code' | 'ciba'

export const METHODS: Array<{ value: Method; label: string; description: string }> = [
  {
    value: 'oidc',
    label: 'OIDC - OpenID Connect',
    description: 'OAuth 2.0 기반 토큰 로그인입니다. 직접 만드는 앱이나 새로 연동하는 앱에 권장합니다.',
  },
  {
    value: 'saml',
    label: 'SAML 2.0',
    description: 'XML 기반 표준 로그인입니다. 연동할 서비스가 SAML만 지원할 때 씁니다.',
  },
  {
    value: 'wsfed',
    label: 'WS-Federation',
    description: 'Microsoft 계열 서비스가 쓰는 수동형 로그인입니다.',
  },
  {
    value: 'swa',
    label: 'SWA - 보안 웹 인증',
    description: '로그인 화면에 계정을 대신 채워 넣는 방식입니다. OIDC나 SAML을 지원하지 않을 때 씁니다.',
  },
  {
    value: 'api',
    label: 'API 서비스',
    description: '사용자 없이 서버끼리 범위가 정해진 OAuth 2.0 토큰으로 API를 호출합니다.',
  },
  {
    value: 'bookmark',
    label: '북마크',
    description: '로그인 연동 없이 포털에 링크만 보여 줍니다.',
  },
]

export const CLIENT_TYPES: Array<{ value: Exclude<ClientType, 'service'>; label: string; description: string }> = [
  {
    value: 'web',
    label: '웹 애플리케이션',
    description: '서버에서 인증과 토큰을 처리하는 앱입니다. (예: Go, Java, ASP.NET, Node.js, PHP)',
  },
  {
    value: 'spa',
    label: '싱글 페이지 애플리케이션',
    description: '브라우저에서 실행되고 클라이언트가 토큰을 받는 앱입니다. (예: JavaScript, Angular, React, Vue)',
  },
  {
    value: 'native',
    label: '네이티브 애플리케이션',
    description: '기기에서 직접 실행되고 HTTP가 아닌 콜백으로 돌아오는 앱입니다. (예: iOS, Android, React Native)',
  },
]

export const PROTOCOL_LABELS: Record<string, string> = {
  bookmark: '북마크',
  oidc: 'OIDC',
  saml: 'SAML',
  wsfed: 'WS-Fed',
  swa: 'SWA',
}

export const CLIENT_TYPE_LABELS: Record<ClientType, string> = {
  web: '웹 애플리케이션',
  spa: '싱글 페이지 애플리케이션',
  native: '네이티브 애플리케이션',
  service: 'API 서비스',
}

export const GRANT_LABELS: Record<GrantKey, { label: string; description: string }> = {
  authorization_code: { label: '인증 코드', description: '사용자가 로그인하고 코드를 받아 토큰으로 바꿉니다.' },
  refresh_token: { label: '리프레시 토큰', description: '다시 로그인하지 않고 토큰을 갱신합니다.' },
  client_credentials: { label: '클라이언트 자격 증명', description: '앱이 자기 자신의 이름으로 토큰을 받습니다.' },
  device_code: { label: '기기 코드', description: '화면이 작거나 입력이 불편한 기기에서 다른 기기로 승인합니다.' },
  ciba: { label: 'CIBA', description: '앱이 요청하면 사용자가 자기 기기에서 승인합니다.' },
}

export type OidcClient = {
  clientId: string
  name: string
  applicationType: ClientType
  confidential: boolean
  grants: GrantKey[]
  redirectUris: string[]
  postLogoutRedirectUris: string[]
  scopes: string[]
  requirePkce: boolean
  dpop: boolean
  disabled: boolean
  backchannelLogoutUri?: string | null
  backchannelLogoutSessionRequired?: boolean
}

export type Integration = {
  protocol: string
  binding: string | null
  issuer: string
  oidc?: OidcClient | null
  saml?: { entityId: string; acsUrl: string; signingCertificate: string } | null
  wsfed?: { realm: string; replyUrl: string } | null
  swa?: { name: string; origin: string } | null
  endpoints?: Record<string, string>
}

export type Assignment = { mode: 'everyone' | 'groups'; groups: Array<{ id: string; name: string }> }

export type DirectoryGroup = { id: string; name: string }

export const groupsQuery = queryOptions({
  queryKey: ['admin', 'groups', 'all'],
  queryFn: async () => (await apiFetch<{ groups: DirectoryGroup[] }>('/api/admin/directory-groups?limit=100')).groups,
})

export const integrationKey = (slug: string) => ['admin', 'application', slug, 'integration'] as const
export const assignmentKey = (slug: string) => ['admin', 'application', slug, 'assignment'] as const

export function integrationQuery(slug: string) {
  return queryOptions({
    queryKey: integrationKey(slug),
    queryFn: () => apiFetch<Integration>(`/api/admin/applications/${slug}/integration`),
  })
}

export function assignmentQuery(slug: string) {
  return queryOptions({
    queryKey: assignmentKey(slug),
    queryFn: () => apiFetch<Assignment>(`/api/admin/applications/${slug}/assignment`),
  })
}

export type Discovery = Record<string, string>

export const discoveryQuery = queryOptions({
  queryKey: ['oidc-discovery'],
  queryFn: async () => {
    const response = await fetch('/.well-known/openid-configuration', { headers: { Accept: 'application/json' } })
    if (!response.ok) throw new Error('discovery')
    return (await response.json()) as Discovery
  },
  staleTime: 5 * 60_000,
})

/** An identifier like `my-web-app` from a display name; empty when nothing usable is left. */
export function slugify(name: string): string {
  return name
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
}

export function parseMethod(value: unknown): Method | null {
  return METHODS.some((method) => method.value === value) ? (value as Method) : null
}

export function parseClientType(value: unknown): Exclude<ClientType, 'service'> {
  return value === 'spa' || value === 'native' ? value : 'web'
}
