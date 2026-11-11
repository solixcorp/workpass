import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, Trash2Icon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'

type Approval = { uri: string; inUseBy: Array<{ clientId: string; applicationName: string }> }
const message = (error: unknown, fallback: string) => (error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : fallback)

/** The addresses an app may be sent a sign-out notice at. Only addresses listed here can be saved on an app. */
export function ApprovalsTab() {
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['admin', 'integrations', 'logout-approvals'], queryFn: () => apiFetch<{ approvals: Approval[] }>('/api/admin/oidc-logout-approvals') })
  const [uri, setUri] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'integrations', 'logout-approvals'] })

  const add = useMutation({
    mutationFn: () => apiFetch('/api/admin/oidc-logout-approvals', { method: 'POST', body: JSON.stringify({ uri: uri.trim() }) }),
    onSuccess: async () => {
      setUri('')
      setFailure(null)
      toast.success('주소를 승인했습니다.')
      await refresh()
    },
    onError: (error) => setFailure(message(error, '승인하지 못했습니다.')),
  })
  const remove = useMutation({
    mutationFn: (value: string) => apiFetch(`/api/admin/oidc-logout-approvals?uri=${encodeURIComponent(value)}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('승인을 뺐습니다.')
      await refresh()
    },
    onError: (error) => toast.error(message(error, '빼지 못했습니다.')),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    if (uri.trim()) add.mutate()
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-2xl text-sm text-muted-foreground">
        앱을 로그아웃시킬 때 이 시스템이 로그아웃 토큰을 보내는 주소입니다. 여기서 승인한 공개 https 주소만 OIDC 앱의 ‘백채널 로그아웃 주소’로 저장할 수 있습니다. 앱이 쓰고 있는 주소는 승인을 뺄 수 없습니다.
      </p>
      <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
        <Input aria-label="승인할 주소" className="max-w-md flex-1" placeholder="https://app.example.com/backchannel-logout" autoComplete="off" spellCheck={false} value={uri} onChange={(event) => setUri(event.target.value)} />
        <Button type="submit" disabled={add.isPending || !uri.trim()}>
          {add.isPending ? <Spinner data-icon="inline-start" /> : <PlusIcon data-icon="inline-start" />}
          승인
        </Button>
      </form>
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      {query.isPending ? (
        <Skeleton className="h-24 w-full" />
      ) : query.error ? (
        <Alert variant="destructive">
          <AlertDescription>승인 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : query.data.approvals.length === 0 ? (
        <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">승인한 주소가 없습니다.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>주소</TableHead>
                <TableHead>쓰는 앱</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.data.approvals.map((approval) => (
                <TableRow key={approval.uri}>
                  <TableCell className="break-all font-mono text-xs">{approval.uri}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {approval.inUseBy.length ? approval.inUseBy.map((app) => <Badge key={app.clientId} variant="secondary">{app.applicationName}</Badge>) : <span className="text-xs text-muted-foreground">쓰는 앱 없음</span>}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon-sm" aria-label="승인 빼기" disabled={approval.inUseBy.length > 0 || remove.isPending} title={approval.inUseBy.length ? '앱이 쓰고 있어 뺄 수 없습니다' : undefined} onClick={() => remove.mutate(approval.uri)}>
                      <Trash2Icon />
                    </Button>
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
