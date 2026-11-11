import { useInfiniteQuery } from '@tanstack/react-query'
import { ShieldCheckIcon, UserIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { apiFetch } from '@/lib/api'
import { eventLabel } from '@/lib/audit-labels'
import { formatDateTime } from '@/lib/format'
import { Failed, Loading, Nothing, Panel } from './shared'

export function RolesTab({ roles }: { roles: string[] }) {
  const isAdmin = roles.includes('admin')
  return (
    <Panel
      title="관리자 역할"
      description="이 시스템의 역할은 관리자와 일반 사용자 두 가지입니다. 맞춤 역할이나 범위가 제한된 관리자는 아직 없습니다. 바꾸려면 위쪽 ⋯ 메뉴를 쓰세요."
    >
      <div className="flex flex-col gap-3">
        <div className="flex items-start gap-3 rounded-xl border bg-card p-4">
          <ShieldCheckIcon className={`mt-0.5 size-4 shrink-0 ${isAdmin ? 'text-primary' : 'text-muted-foreground'}`} />
          <div className="flex flex-col gap-0.5">
            <span className="flex items-center gap-2 text-sm font-medium">
              관리자 {isAdmin ? <Badge>부여됨</Badge> : <Badge variant="outline">없음</Badge>}
            </span>
            <span className="text-xs text-muted-foreground">사용자, 그룹, 앱, 정책, 설정, 감사 로그를 포함한 관리 콘솔 전체를 다룰 수 있습니다.</span>
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-xl border bg-card p-4">
          <UserIcon className="mt-0.5 size-4 shrink-0 text-primary" />
          <div className="flex flex-col gap-0.5">
            <span className="flex items-center gap-2 text-sm font-medium">
              사용자 <Badge variant="secondary">기본</Badge>
            </span>
            <span className="text-xs text-muted-foreground">할당된 앱을 열고 자신의 보안 설정을 관리합니다.</span>
          </div>
        </div>
      </div>
    </Panel>
  )
}

type AuditEvent = {
  id: string
  occurred_at: string
  actor_user_id: string | null
  target_user_id: string | null
  event_type: string
  outcome: 'started' | 'success' | 'failure'
  client_ip: string | null
}

const OUTCOMES = { success: '성공', failure: '실패', started: '시작' } as const

export function LogsTab({ id }: { id: string }) {
  const query = useInfiniteQuery({
    queryKey: ['admin', 'users', 'detail', id, 'logs'],
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ userId: id, limit: '25' })
      if (pageParam) params.set('cursor', pageParam)
      return apiFetch<{ events: AuditEvent[]; nextCursor: string | null }>(`/api/admin/audit-events?${params}`)
    },
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  })
  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="시스템 로그" />
  const events = query.data.pages.flatMap((page) => page.events)
  return (
    <Panel title="시스템 로그" description="이 사용자가 한 일과 이 사용자에게 일어난 일입니다.">
      {events.length === 0 ? (
        <Nothing>기록이 없습니다.</Nothing>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>시각</TableHead>
                <TableHead>내용</TableHead>
                <TableHead>구분</TableHead>
                <TableHead>결과</TableHead>
                <TableHead>IP</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((event) => (
                <TableRow key={event.id}>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(event.occurred_at)}</TableCell>
                  <TableCell className="font-medium">{eventLabel(event.event_type)}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{event.target_user_id === id && event.actor_user_id !== id ? '이 사용자에게' : '이 사용자가'}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={event.outcome === 'failure' ? 'destructive' : 'secondary'}>{OUTCOMES[event.outcome]}</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{event.client_ip ?? '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {query.hasNextPage ? (
        <div>
          <Button variant="outline" size="sm" disabled={query.isFetchingNextPage} onClick={() => query.fetchNextPage()}>
            더 보기
          </Button>
        </div>
      ) : null}
    </Panel>
  )
}
