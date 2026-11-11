import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { SearchIcon, XIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Paginator } from '@/components/paginator'
import { apiFetch } from '@/lib/api'
import { EVENT_FAMILIES, eventLabel } from '@/lib/audit-labels'
import { formatDateTime } from '@/lib/format'
import { AuditDetail } from './audit-detail'
import type { AuditEvent, AuditPage } from './types'

const RANGES = [
  { value: 'all', label: '전체 기간', ms: 0 },
  { value: '1h', label: '최근 1시간', ms: 3_600_000 },
  { value: '24h', label: '최근 24시간', ms: 86_400_000 },
  { value: '7d', label: '최근 7일', ms: 7 * 86_400_000 },
  { value: '30d', label: '최근 30일', ms: 30 * 86_400_000 },
]

const OUTCOMES = { success: '성공', failure: '실패', started: '시작' } as const
const OUTCOME_VARIANTS = { success: 'secondary', failure: 'destructive', started: 'outline' } as const

type Filters = { family: string; outcome: string; range: string; text: string }
const NO_FILTERS: Filters = { family: 'all', outcome: 'all', range: 'all', text: '' }

function Pick({ label, value, onChange, children }: { label: string; value: string; onChange: (value: string) => void; children: React.ReactNode }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger aria-label={label} className="w-40">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>{children}</SelectGroup>
      </SelectContent>
    </Select>
  )
}

/**
 * The audit log: filters, numbered pages, and a panel that opens one event in
 * full. With `userId` it shows what one person did and what was done to them.
 */
export function AuditView({ userId, keyPrefix }: { userId?: string; keyPrefix: string }) {
  const [filters, setFilters] = useState<Filters>(NO_FILTERS)
  const [draft, setDraft] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [open, setOpen] = useState<AuditEvent | null>(null)

  const query = useQuery({
    queryKey: [keyPrefix, 'audit', userId ?? null, filters, page, pageSize],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), limit: String(pageSize) })
      if (userId) params.set('userId', userId)
      const family = EVENT_FAMILIES.find((entry) => entry.value === filters.family)
      if (family) params.set('eventPrefix', family.prefix)
      if (filters.outcome !== 'all') params.set('outcome', filters.outcome)
      const range = RANGES.find((entry) => entry.value === filters.range)
      if (range && range.ms) params.set('from', new Date(Date.now() - range.ms).toISOString())
      if (filters.text) params.set('q', filters.text)
      return apiFetch<AuditPage>(`/api/admin/audit-events?${params}`)
    },
    placeholderData: keepPreviousData,
  })

  const change = (next: Partial<Filters>) => {
    setFilters({ ...filters, ...next })
    setPage(1)
  }
  const submit = (event: FormEvent) => {
    event.preventDefault()
    change({ text: draft.trim() })
  }
  const filtered = JSON.stringify(filters) !== JSON.stringify(NO_FILTERS)
  const events = query.data?.events ?? []
  const total = query.data?.total ?? 0

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Pick label="이벤트 종류" value={filters.family} onChange={(value) => change({ family: value })}>
          <SelectItem value="all">모든 종류</SelectItem>
          {EVENT_FAMILIES.map((entry) => (
            <SelectItem key={entry.value} value={entry.value}>
              {entry.label}
            </SelectItem>
          ))}
        </Pick>
        <Pick label="결과" value={filters.outcome} onChange={(value) => change({ outcome: value })}>
          <SelectItem value="all">모든 결과</SelectItem>
          <SelectItem value="success">성공</SelectItem>
          <SelectItem value="failure">실패</SelectItem>
          <SelectItem value="started">시작</SelectItem>
        </Pick>
        <Pick label="기간" value={filters.range} onChange={(value) => change({ range: value })}>
          {RANGES.map((entry) => (
            <SelectItem key={entry.value} value={entry.value}>
              {entry.label}
            </SelectItem>
          ))}
        </Pick>
        <form onSubmit={submit} className="flex items-center gap-2">
          <Input aria-label="이벤트·경로·IP 검색" placeholder="이벤트, 경로, IP 검색" className="w-56" value={draft} onChange={(event) => setDraft(event.target.value)} />
          <Button type="submit" variant="outline" size="icon" aria-label="검색">
            <SearchIcon />
          </Button>
        </form>
        {filtered ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setDraft('')
              change(NO_FILTERS)
            }}
          >
            <XIcon data-icon="inline-start" />
            필터 지우기
          </Button>
        ) : null}
      </div>

      {query.error ? (
        <Alert variant="destructive">
          <AlertDescription>감사 로그를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : query.isPending ? (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 8 }, (_, index) => (
            <Skeleton key={index} className="h-11 rounded-md" />
          ))}
        </div>
      ) : events.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>조건에 맞는 이벤트가 없습니다</EmptyTitle>
            <EmptyDescription>필터를 바꾸거나 지워 보세요.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <>
          <div className={`overflow-x-auto rounded-xl border transition-opacity ${query.isPlaceholderData ? 'opacity-60' : ''}`}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>시각</TableHead>
                  <TableHead>이벤트</TableHead>
                  {userId ? <TableHead>구분</TableHead> : <><TableHead>행위자</TableHead><TableHead>대상</TableHead></>}
                  <TableHead>결과</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((event) => (
                  <TableRow key={event.id} className="cursor-pointer" tabIndex={0} onClick={() => setOpen(event)} onKeyDown={(key) => key.key === 'Enter' && setOpen(event)}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(event.occurred_at)}</TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{eventLabel(event.event_type)}</span>
                        {eventLabel(event.event_type) !== event.event_type ? <span className="font-mono text-xs text-muted-foreground">{event.event_type}</span> : null}
                      </div>
                    </TableCell>
                    {userId ? (
                      <TableCell>
                        {event.target_user_id === userId && event.actor_user_id !== userId ? (
                          <Badge variant="outline">{event.actor ? `${event.actor.name}이(가) 함` : '이 사용자에게'}</Badge>
                        ) : (
                          <Badge variant="outline">이 사용자가</Badge>
                        )}
                      </TableCell>
                    ) : (
                      <>
                        <TableCell className="text-sm">{event.actor?.name ?? <span className="text-muted-foreground">{event.actor_user_id ? '삭제된 사용자' : '—'}</span>}</TableCell>
                        <TableCell className="text-sm">{event.target?.name ?? <span className="text-muted-foreground">{event.target_user_id ?? '—'}</span>}</TableCell>
                      </>
                    )}
                    <TableCell>
                      <Badge variant={OUTCOME_VARIANTS[event.outcome]}>{OUTCOMES[event.outcome]}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{event.client_ip ?? '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <Paginator
            page={page}
            pageSize={pageSize}
            total={total}
            onPage={setPage}
            onPageSize={(size) => {
              setPageSize(size)
              setPage(1)
            }}
          />
        </>
      )}
      <AuditDetail event={open} onClose={() => setOpen(null)} />
    </div>
  )
}
