import { useInfiniteQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type AuditEvent = {
  id: string
  occurred_at: string
  actor_user_id: string | null
  target_user_id: string | null
  event_type: string
  outcome: 'started' | 'success' | 'failure'
  request_path: string
  client_ip: string | null
}

type AuditPage = { events: AuditEvent[]; nextCursor: string | null }

const OUTCOME_LABELS: Record<AuditEvent['outcome'], string> = {
  success: '성공',
  failure: '실패',
  started: '시작',
}

const OUTCOME_VARIANTS: Record<AuditEvent['outcome'], 'secondary' | 'destructive' | 'outline'> = {
  success: 'secondary',
  failure: 'destructive',
  started: 'outline',
}

type Filters = { eventType: string; outcome: string }

export function AuditPage() {
  const [draft, setDraft] = useState<Filters>({ eventType: '', outcome: 'all' })
  const [filters, setFilters] = useState<Filters>(draft)

  const query = useInfiniteQuery({
    queryKey: ['admin', 'audit', filters],
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ limit: '50' })
      if (filters.eventType.trim()) params.set('eventType', filters.eventType.trim())
      if (filters.outcome !== 'all') params.set('outcome', filters.outcome)
      if (pageParam) params.set('cursor', pageParam)
      return apiFetch<AuditPage>(`/api/admin/audit-events?${params.toString()}`)
    },
    getNextPageParam: (last) => last.nextCursor,
  })

  const events = query.data?.pages.flatMap((page) => page.events) ?? []

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <h1 className="text-2xl font-semibold">감사 로그</h1>

      <form
        className="flex flex-col gap-4 sm:flex-row sm:items-end"
        onSubmit={(event) => {
          event.preventDefault()
          setFilters(draft)
        }}
      >
        <FieldGroup className="sm:flex-row sm:items-end">
          <Field className="sm:max-w-xs">
            <FieldLabel htmlFor="audit-event-type">이벤트 종류</FieldLabel>
            <Input
              id="audit-event-type"
              placeholder="authentication.workpass.login"
              value={draft.eventType}
              onChange={(event) => setDraft({ ...draft, eventType: event.target.value })}
            />
          </Field>
          <Field className="sm:max-w-40">
            <FieldLabel htmlFor="audit-outcome">결과</FieldLabel>
            <Select value={draft.outcome} onValueChange={(value) => setDraft({ ...draft, outcome: value })}>
              <SelectTrigger id="audit-outcome" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">전체</SelectItem>
                  <SelectItem value="success">성공</SelectItem>
                  <SelectItem value="failure">실패</SelectItem>
                  <SelectItem value="started">시작</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
          <Field className="sm:w-auto">
            <Button type="submit">검색</Button>
          </Field>
        </FieldGroup>
      </form>

      {query.error ? (
        <Alert variant="destructive">
          <AlertDescription>감사 로그를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : query.isPending ? (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 6 }, (_, index) => (
            <Skeleton key={index} className="h-10 rounded-md" />
          ))}
        </div>
      ) : events.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>조건에 맞는 이벤트가 없습니다</EmptyTitle>
            <EmptyDescription>검색 조건을 바꿔 보세요.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>시각</TableHead>
                  <TableHead>이벤트</TableHead>
                  <TableHead>결과</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>경로</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">
                      {formatDateTime(event.occurred_at)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{event.event_type}</TableCell>
                    <TableCell>
                      <Badge variant={OUTCOME_VARIANTS[event.outcome]}>
                        {OUTCOME_LABELS[event.outcome]}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {event.client_ip ?? '—'}
                    </TableCell>
                    <TableCell className="max-w-64 truncate font-mono text-xs text-muted-foreground">
                      {event.request_path}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {query.hasNextPage ? (
            <Button
              variant="outline"
              className="self-center"
              disabled={query.isFetchingNextPage}
              onClick={() => query.fetchNextPage()}
            >
              {query.isFetchingNextPage ? <Spinner data-icon="inline-start" /> : null}
              더 보기
            </Button>
          ) : null}
        </>
      )}
    </div>
  )
}
