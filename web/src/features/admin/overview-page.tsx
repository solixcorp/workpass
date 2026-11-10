import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { apiFetch } from '@/lib/api'

type UsageSnapshot = { capturedAt: string; counts: Record<string, number> }

const METRICS: Array<{ key: string; label: string; to?: string }> = [
  { key: 'user', label: '사용자', to: '/admin/users' },
  { key: 'session', label: '활성 세션' },
  { key: 'directory_groups', label: '그룹' },
  { key: 'oauthClient', label: 'OIDC 클라이언트' },
  { key: 'saml_service_providers', label: 'SAML SP' },
  { key: 'audit_events', label: '감사 이벤트', to: '/admin/audit' },
]

export function AdminOverviewPage() {
  const { data, isPending, error } = useQuery({
    queryKey: ['admin', 'usage'],
    queryFn: () => apiFetch<UsageSnapshot>('/api/admin/usage-snapshot'),
  })

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <h1 className="text-2xl font-semibold">관리 개요</h1>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>사용량 정보를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : (
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl bg-border md:grid-cols-3">
          {METRICS.map((metric) => {
            const value = data?.counts[metric.key]
            const body = (
              <>
                <span className="text-sm text-muted-foreground">{metric.label}</span>
                {isPending ? (
                  <Skeleton className="h-7 w-16" />
                ) : (
                  <span className="text-2xl font-semibold tabular-nums">
                    {value === undefined || value < 0 ? '—' : value.toLocaleString('ko-KR')}
                  </span>
                )}
              </>
            )
            return metric.to ? (
              <Link
                key={metric.key}
                to={metric.to}
                className="flex flex-col gap-1 bg-background p-4 transition-colors hover:bg-muted/50"
              >
                {body}
              </Link>
            ) : (
              <div key={metric.key} className="flex flex-col gap-1 bg-background p-4">
                {body}
              </div>
            )
          })}
        </div>
      )}
      {data ? (
        <p className="text-xs text-muted-foreground">
          {new Date(data.capturedAt).toLocaleString('ko-KR')} 기준
        </p>
      ) : null}
    </div>
  )
}
