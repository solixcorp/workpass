import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { UnplugIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { scopeLabel } from '@/features/approvals/scopes'

type Connected = { clientId: string; slug: string | null; applicationName: string; activeTokens: number; lastIssuedAt: string | null; consentGrantedAt: string | null; scopes: string[] }

/** Apps the person has allowed to sign them in, with a way to take that back. */
export function ConnectedApps() {
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['me', 'connected-apps'], queryFn: () => apiFetch<{ apps: Connected[] }>('/api/me/connected-apps') })
  const [target, setTarget] = useState<Connected | null>(null)
  const disconnect = useMutation({
    mutationFn: (app: Connected) => apiFetch(`/api/me/connected-apps/${encodeURIComponent(app.clientId)}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('연결을 해제했습니다.')
      setTarget(null)
      await queryClient.invalidateQueries({ queryKey: ['me', 'connected-apps'] })
    },
    onError: () => {
      setTarget(null)
      toast.error('해제하지 못했습니다.')
    },
  })

  return (
    <section className="flex flex-col gap-1 rounded-2xl border bg-card p-6">
      <h2 className="pb-2 text-sm font-semibold">연결된 앱</h2>
      {query.isPending ? (
        <Skeleton className="h-16 w-full" />
      ) : query.error ? (
        <Alert variant="destructive">
          <AlertDescription>연결된 앱을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : query.data.apps.length === 0 ? (
        <p className="py-3 text-sm text-muted-foreground">내 계정으로 로그인을 허용한 앱이 없습니다.</p>
      ) : (
        query.data.apps.map((app) => (
          <div key={app.clientId} className="flex items-start justify-between gap-4 border-b py-3 last:border-b-0">
            <div className="flex min-w-0 flex-col gap-0.5">
              <span className="truncate text-sm font-medium">{app.applicationName}</span>
              <span className="text-xs text-muted-foreground">
                {app.scopes.map((scope) => scopeLabel(scope).title).join(', ') || '기본 신원 확인'}
                {app.consentGrantedAt ? ` · ${formatDateTime(app.consentGrantedAt)}에 허용` : ''}
              </span>
            </div>
            <Button variant="outline" size="sm" onClick={() => setTarget(app)}>
              <UnplugIcon data-icon="inline-start" />
              연결 해제
            </Button>
          </div>
        ))
      )}
      <p className="pt-3 text-xs text-muted-foreground">해제하면 그 앱이 받아 둔 토큰이 폐기되고 허용 기록이 지워져, 다음에 앱을 열 때 다시 허용을 묻습니다.</p>
      <AlertDialog open={target !== null} onOpenChange={(open) => !open && !disconnect.isPending && setTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{target?.applicationName} 연결을 해제할까요?</AlertDialogTitle>
            <AlertDialogDescription>이 앱에서 로그아웃되고, 다시 쓰려면 로그인과 허용을 새로 해야 합니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={disconnect.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={disconnect.isPending} onClick={(event) => { event.preventDefault(); if (target) disconnect.mutate(target) }}>
              해제
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  )
}
