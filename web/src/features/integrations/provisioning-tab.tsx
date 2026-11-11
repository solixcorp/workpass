import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Paginator } from '@/components/paginator'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import type { Paged, ScimOperation } from './types'

const STATUS: Record<ScimOperation['status'], { label: string; variant: 'secondary' | 'destructive' | 'outline' | 'default' }> = {
  succeeded: { label: '성공', variant: 'secondary' },
  failed: { label: '실패', variant: 'destructive' },
  pending: { label: '대기', variant: 'outline' },
  in_progress: { label: '진행 중', variant: 'outline' },
  outcome_unknown: { label: '결과 불명', variant: 'destructive' },
}
const OPERATIONS = { create: '생성', update: '수정', deactivate: '비활성화' } as const

/** What was sent to the external system for which user, and how it went. */
export function ProvisioningTab() {
  const [status, setStatus] = useState('all')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const query = useQuery({
    queryKey: ['admin', 'integrations', 'scim', status, page, pageSize],
    queryFn: () => apiFetch<Paged<'operations', ScimOperation>>(`/api/admin/scim-operations?${new URLSearchParams({ page: String(page), limit: String(pageSize), ...(status === 'all' ? {} : { status }) })}`),
    placeholderData: keepPreviousData,
  })
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">사용자 변경을 외부 시스템에 보낸 기록입니다. 결과 불명은 응답을 받지 못해 반영 여부를 알 수 없다는 뜻이니 외부 시스템에서 직접 확인하세요.</p>
        <Select value={status} onValueChange={(value) => { setStatus(value); setPage(1) }}>
          <SelectTrigger aria-label="상태" className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">모든 상태</SelectItem>
              {(Object.keys(STATUS) as Array<ScimOperation['status']>).map((key) => (
                <SelectItem key={key} value={key}>
                  {STATUS[key].label}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>
      {query.error ? (
        <Alert variant="destructive">
          <AlertDescription>기록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : query.isPending ? (
        <Skeleton className="h-48 w-full" />
      ) : query.data.operations.length === 0 ? (
        <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">보낸 기록이 없습니다.</p>
      ) : (
        <>
          <div className={`overflow-x-auto rounded-xl border ${query.isPlaceholderData ? 'opacity-60' : ''}`}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>시각</TableHead>
                  <TableHead>사용자</TableHead>
                  <TableHead>작업</TableHead>
                  <TableHead>결과</TableHead>
                  <TableHead>응답 코드</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {query.data.operations.map((operation) => (
                  <TableRow key={operation.id}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(operation.updated_at)}</TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{operation.user_name ?? '삭제된 사용자'}</span>
                        <span className="text-xs text-muted-foreground">{operation.user_email ?? operation.user_id}</span>
                      </div>
                    </TableCell>
                    <TableCell>{OPERATIONS[operation.operation]}</TableCell>
                    <TableCell>
                      <Badge variant={STATUS[operation.status].variant}>{STATUS[operation.status].label}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{operation.remote_status ?? '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <Paginator page={page} pageSize={pageSize} total={query.data.total} onPage={setPage} onPageSize={(size) => { setPageSize(size); setPage(1) }} />
        </>
      )}
    </div>
  )
}
