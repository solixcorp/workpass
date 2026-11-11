import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type Report = { id: string; userId: string; name: string | null; email: string | null; summary: string; createdAt: string; status: 'open' | 'closed'; handledAt: string | null }

/** What people reported as not theirs, newest first. */
export function ReportsPage() {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<'open' | 'closed'>('open')
  const query = useQuery({
    queryKey: ['admin', 'reports', status],
    queryFn: () => apiFetch<{ reports: Report[] }>(`/api/admin/suspicious-reports?status=${status}`),
  })
  const close = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/suspicious-reports/${id}/close`, { method: 'POST', body: '{}' }),
    onSuccess: async () => {
      toast.success('확인했습니다. 신고한 사용자에게 알렸습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'reports'] })
      await queryClient.invalidateQueries({ queryKey: ['admin', 'overview'] })
    },
    onError: () => toast.error('처리하지 못했습니다.'),
  })

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">의심스러운 활동 신고</h1>
        <p className="text-sm text-muted-foreground">사용자가 내가 한 것이 아니라고 알린 로그인과 활동입니다. 계정 확인이 끝나면 처리 완료로 바꾸세요.</p>
      </div>
      <Tabs value={status} onValueChange={(value) => setStatus(value as typeof status)}>
        <TabsList variant="line">
          <TabsTrigger value="open">처리 전</TabsTrigger>
          <TabsTrigger value="closed">처리 완료</TabsTrigger>
        </TabsList>
      </Tabs>
      {query.error ? (
        <Alert variant="destructive">
          <AlertDescription>신고를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : query.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : query.data.reports.length === 0 ? (
        <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">{status === 'open' ? '처리할 신고가 없습니다.' : '처리한 신고가 없습니다.'}</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>사용자</TableHead>
                <TableHead>내용</TableHead>
                <TableHead>신고 시각</TableHead>
                <TableHead className="w-28" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.data.reports.map((report) => (
                <TableRow key={report.id}>
                  <TableCell>
                    <Link to="/admin/users/$id" params={{ id: report.userId }} className="flex flex-col hover:underline">
                      <span className="font-medium">{report.name ?? '삭제된 사용자'}</span>
                      <span className="text-xs text-muted-foreground">{report.email}</span>
                    </Link>
                  </TableCell>
                  <TableCell className="max-w-md whitespace-normal text-muted-foreground">{report.summary}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(report.createdAt)}</TableCell>
                  <TableCell className="text-right">
                    {report.status === 'open' ? (
                      <Button variant="outline" size="sm" disabled={close.isPending} onClick={() => close.mutate(report.id)}>
                        처리 완료
                      </Button>
                    ) : (
                      <span className="text-xs text-muted-foreground">{report.handledAt ? formatDateTime(report.handledAt) : ''}</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
