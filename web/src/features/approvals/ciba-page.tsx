import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ApiError, apiFetch } from '@/lib/api'
import { ScopeList } from './approval-card'

type Request = { id: string; clientName: string; scopes: string[]; bindingMessage: string | null; expiresAt: number }

const pendingQuery = {
  queryKey: ['ciba', 'pending'],
  queryFn: () => apiFetch<{ requests: Request[] }>('/api/ciba/pending'),
  refetchInterval: 10_000,
  retry: false,
}

/** Sign-in requests an app started for this person, waiting for an answer. */
export function CibaPage() {
  const queryClient = useQueryClient()
  const pending = useQuery(pendingQuery)
  const decide = useMutation({
    mutationFn: ({ id, approve }: { id: string; approve: boolean }) =>
      apiFetch('/api/ciba/decide', { method: 'POST', body: JSON.stringify({ request: id, decision: approve ? 'approve' : 'deny' }) }),
    onSuccess: async (_, { approve }) => {
      toast.success(approve ? '승인했습니다.' : '거절했습니다.')
      await queryClient.invalidateQueries({ queryKey: pendingQuery.queryKey })
    },
    onError: async () => {
      toast.error('처리하지 못했습니다. 요청이 이미 처리되었거나 만료되었을 수 있습니다.')
      await queryClient.invalidateQueries({ queryKey: pendingQuery.queryKey })
    },
  })

  return (
    <div className="mx-auto flex w-full max-w-2xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">로그인 승인 요청</h1>
        <p className="text-sm text-muted-foreground">앱이 내 계정으로 로그인하려고 할 때 여기서 승인하거나 거절합니다. 요청은 5분 뒤 만료됩니다.</p>
      </div>
      {pending.isPending ? (
        <Skeleton className="h-32 w-full" />
      ) : pending.error ? (
        <Alert variant={pending.error instanceof ApiError && pending.error.status === 404 ? 'default' : 'destructive'}>
          <AlertDescription>
            {pending.error instanceof ApiError && pending.error.status === 404 ? '이 기능은 사용하지 않도록 설정되어 있습니다.' : '요청을 불러오지 못했습니다.'}
          </AlertDescription>
        </Alert>
      ) : pending.data.requests.length === 0 ? (
        <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">승인을 기다리는 요청이 없습니다.</p>
      ) : (
        pending.data.requests.map((request) => (
          <div key={request.id} className="flex flex-col gap-4 rounded-2xl border bg-card p-6">
            <p className="text-sm">
              앱 <strong>{request.clientName}</strong>이(가) 로그인을 요청합니다.
            </p>
            {request.bindingMessage ? <p className="rounded-lg bg-muted px-3 py-2 text-sm">“{request.bindingMessage}”</p> : null}
            <ScopeList scopes={request.scopes} />
            <div className="flex gap-2">
              <Button disabled={decide.isPending} onClick={() => decide.mutate({ id: request.id, approve: true })}>
                승인
              </Button>
              <Button variant="outline" disabled={decide.isPending} onClick={() => decide.mutate({ id: request.id, approve: false })}>
                거절
              </Button>
            </div>
          </div>
        ))
      )}
    </div>
  )
}
