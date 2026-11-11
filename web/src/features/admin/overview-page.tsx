import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { ChevronRightIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { apiFetch } from '@/lib/api'
import { eventLabel } from '@/lib/audit-labels'
import { formatDateTime } from '@/lib/format'

type Overview = {
  counts: { users: number; activeUsers: number; groups: number; apps: number; enabledApps: number }
  services: Array<{ name: string; state: 'ok' | 'off'; note: string }>
  tasks: Array<{ id: string; title: string; count: number; to: string; severity: 'high' | 'normal' }>
  changes: Array<{ id: string; at: string; type: string; outcome: string; actor: string | null }>
  security: {
    windowDays: number
    protectedUsers: number
    activeUsers: number
    threats: { failedSignIns: number; riskStepUps: number; riskDenied: number; locationViolations: number; lockdowns: number }
    openReports: number
  }
}

function Card({ title, to, children }: { title: string; to?: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-4 rounded-2xl border bg-card p-6">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">{title}</h2>
        {to ? (
          <Link to={to} className="flex items-center text-xs text-muted-foreground hover:text-foreground">
            자세히
            <ChevronRightIcon className="size-3.5" />
          </Link>
        ) : null}
      </div>
      {children}
    </section>
  )
}

function Tile({ label, value, sub, to }: { label: string; value: number; sub?: string; to: string }) {
  return (
    <Link to={to} className="flex flex-col gap-1 rounded-2xl border bg-card p-5 transition-colors hover:bg-muted/50">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-2xl font-semibold tabular-nums">{value.toLocaleString('ko-KR')}</span>
      {sub ? <span className="text-xs text-muted-foreground">{sub}</span> : null}
    </Link>
  )
}

/** A progress ring: how much of the active organization has a second factor or a passkey. */
function Ring({ percent }: { percent: number }) {
  const radius = 42
  const circumference = 2 * Math.PI * radius
  return (
    <div className="relative size-28 shrink-0">
      <svg viewBox="0 0 100 100" className="size-full -rotate-90" role="img" aria-label={`보호된 사용자 ${percent}%`}>
        <circle cx="50" cy="50" r={radius} fill="none" strokeWidth="9" className="stroke-muted" />
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          strokeWidth="9"
          strokeLinecap="round"
          className="stroke-primary"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - percent / 100)}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-semibold tabular-nums">{percent}%</span>
      </div>
    </div>
  )
}

const THREATS: Array<{ key: keyof Overview['security']['threats']; label: string }> = [
  { key: 'failedSignIns', label: '실패한 로그인' },
  { key: 'riskStepUps', label: '기기 위험으로 추가 인증을 요구한 로그인' },
  { key: 'riskDenied', label: '기기 위험으로 거절한 로그인' },
  { key: 'locationViolations', label: '위치가 바뀌어 끊긴 세션' },
  { key: 'lockdowns', label: '계정 잠금' },
]

export function AdminOverviewPage() {
  const { data, isPending, error } = useQuery({
    queryKey: ['admin', 'overview'],
    queryFn: () => apiFetch<Overview>('/api/admin/overview'),
  })

  if (error) {
    return (
      <div className="mx-auto w-full max-w-6xl">
        <Alert variant="destructive">
          <AlertDescription>개요를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      </div>
    )
  }
  if (isPending) {
    return (
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-4">
        <Skeleton className="h-8 w-32" />
        <div className="grid gap-4 md:grid-cols-3">
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
          <Skeleton className="h-24" />
        </div>
        <Skeleton className="h-64" />
      </div>
    )
  }

  const { counts, services, tasks, changes, security } = data
  const percent = security.activeUsers ? Math.round((security.protectedUsers / security.activeUsers) * 100) : 0
  const totalThreats = Object.values(security.threats).reduce((sum, n) => sum + n, 0)

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <h1 className="text-xl font-semibold">개요</h1>

      <div className="grid gap-4 md:grid-cols-3">
        <Tile label="사용자" value={counts.users} sub={`활성 ${counts.activeUsers.toLocaleString('ko-KR')}명`} to="/admin/users" />
        <Tile label="그룹" value={counts.groups} to="/admin/groups" />
        <Tile label="앱" value={counts.apps} sub={`켜짐 ${counts.enabledApps}개`} to="/admin/applications" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="상태">
          <ul className="flex flex-col gap-3">
            {services.map((service) => (
              <li key={service.name} className="flex items-center justify-between gap-3 text-sm">
                <span className="flex items-center gap-2">
                  <span className={`size-2 rounded-full ${service.state === 'ok' ? 'bg-primary' : 'bg-muted-foreground/40'}`} aria-hidden />
                  {service.name}
                </span>
                <span className="text-xs text-muted-foreground">{service.note}</span>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="해야 할 일">
          {tasks.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">지금 처리할 일이 없습니다.</p>
          ) : (
            <ul className="flex flex-col divide-y">
              {tasks.map((task) => (
                <li key={task.id}>
                  <Link to={task.to} className="flex items-center justify-between gap-3 py-3 text-sm hover:text-primary">
                    <span>{task.title}</span>
                    <Badge variant={task.severity === 'high' ? 'destructive' : 'secondary'}>{task.count}</Badge>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="조직 변경" to="/admin/audit">
          {changes.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">최근 변경이 없습니다.</p>
          ) : (
            <ul className="flex flex-col divide-y">
              {changes.map((change) => (
                <li key={change.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                  <span className="flex min-w-0 flex-col">
                    <span className="truncate">{eventLabel(change.type)}</span>
                    <span className="text-xs text-muted-foreground">{change.actor ?? '시스템'}</span>
                  </span>
                  <span className="shrink-0 text-xs text-muted-foreground">{formatDateTime(change.at)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="보안 모니터링" to="/admin/reports">
          <div className="flex items-center gap-6">
            <Ring percent={percent} />
            <div className="flex flex-col gap-1">
              <span className="text-sm font-medium">2차 인증·패스키를 등록한 사용자</span>
              <span className="text-xs text-muted-foreground">
                활성 사용자 {security.activeUsers.toLocaleString('ko-KR')}명 중 {security.protectedUsers.toLocaleString('ko-KR')}명
              </span>
            </div>
          </div>
          <div className="flex flex-col gap-2 border-t pt-4">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium">최근 {security.windowDays}일 위협 신호</span>
              <Badge variant={totalThreats ? 'secondary' : 'outline'}>{totalThreats}</Badge>
            </div>
            <ul className="flex flex-col gap-1.5">
              {THREATS.map((threat) => (
                <li key={threat.key} className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>{threat.label}</span>
                  <span className="tabular-nums">{security.threats[threat.key]}</span>
                </li>
              ))}
              <li className="flex items-center justify-between text-xs text-muted-foreground">
                <span>사용자가 신고한 의심스러운 활동 (처리 전)</span>
                <span className={`tabular-nums ${security.openReports ? 'font-medium text-destructive' : ''}`}>{security.openReports}</span>
              </li>
            </ul>
          </div>
        </Card>
      </div>
    </div>
  )
}
