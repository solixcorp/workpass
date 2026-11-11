import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Paginator } from '@/components/paginator'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import type { Paged, SignalEvent, Stream } from './types'

const DIRECTION = { sender: '보냄', receiver: '받음' } as const

/** Shared Signals streams and the events that passed through them. */
export function SignalsTab() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const streams = useQuery({ queryKey: ['admin', 'integrations', 'streams'], queryFn: () => apiFetch<{ streams: Stream[] }>('/api/admin/ssf/streams') })
  const events = useQuery({
    queryKey: ['admin', 'integrations', 'events', page, pageSize],
    queryFn: () => apiFetch<Paged<'events', SignalEvent>>(`/api/admin/ssf/events?page=${page}&limit=${pageSize}`),
    placeholderData: keepPreviousData,
  })
  return (
    <div className="flex flex-col gap-8">
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">스트림</h2>
        {streams.error ? (
          <Alert variant="destructive">
            <AlertDescription>스트림을 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : streams.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : streams.data.streams.length === 0 ? (
          <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">연결된 스트림이 없습니다.</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>스트림</TableHead>
                  <TableHead>방향</TableHead>
                  <TableHead>전달 방식</TableHead>
                  <TableHead>상대 주소</TableHead>
                  <TableHead>상태</TableHead>
                  <TableHead>전달 / 실패</TableHead>
                  <TableHead>마지막 이벤트</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {streams.data.streams.map((stream) => (
                  <TableRow key={`${stream.direction}-${stream.id}`}>
                    <TableCell className="font-mono text-xs">{stream.id}</TableCell>
                    <TableCell>{DIRECTION[stream.direction]}</TableCell>
                    <TableCell className="text-muted-foreground">{stream.deliveryMethod}</TableCell>
                    <TableCell className="text-muted-foreground">{stream.endpointHost ?? '—'}</TableCell>
                    <TableCell>
                      <Badge variant={stream.status === 'enabled' ? 'secondary' : 'outline'}>{stream.status === 'enabled' ? '켜짐' : stream.status}</Badge>
                    </TableCell>
                    <TableCell className="tabular-nums text-muted-foreground">{stream.eventsDelivered === null ? '—' : `${stream.eventsDelivered} / ${stream.eventsFailed ?? 0}`}</TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{stream.lastEventAt ? formatDateTime(stream.lastEventAt) : '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">최근 이벤트</h2>
        {events.error ? (
          <Alert variant="destructive">
            <AlertDescription>이벤트를 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : events.isPending ? (
          <Skeleton className="h-32 w-full" />
        ) : events.data.events.length === 0 ? (
          <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">주고받은 이벤트가 없습니다.</p>
        ) : (
          <>
            <div className={`overflow-x-auto rounded-xl border ${events.isPlaceholderData ? 'opacity-60' : ''}`}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>시각</TableHead>
                    <TableHead>스트림</TableHead>
                    <TableHead>방향</TableHead>
                    <TableHead>상태</TableHead>
                    <TableHead>시도</TableHead>
                    <TableHead>응답 코드</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.data.events.map((event) => (
                    <TableRow key={`${event.direction}-${event.id}`}>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(event.occurredAt)}</TableCell>
                      <TableCell className="font-mono text-xs">{event.streamId}</TableCell>
                      <TableCell>{DIRECTION[event.direction]}</TableCell>
                      <TableCell>
                        <Badge variant={event.state === 'delivered' ? 'secondary' : 'outline'}>{event.state}</Badge>
                      </TableCell>
                      <TableCell className="tabular-nums text-muted-foreground">{event.attempts ?? '—'}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{event.httpStatus ?? '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Paginator page={page} pageSize={pageSize} total={events.data.total} onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1) }} />
          </>
        )}
      </section>
    </div>
  )
}
