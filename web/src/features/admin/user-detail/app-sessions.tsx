import { useMutation, useQueryClient } from '@tanstack/react-query'
import { LogOutIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { Failed, Loading, Nothing, Panel, useUserData } from './shared'

type AppSession = { clientId: string; slug: string | null; applicationName: string; activeTokens: number; lastIssuedAt: string | null; backchannelLogout: boolean }
type RevokeResult = { revokedTokens: number; apps: Array<{ clientId: string; applicationName: string; status: 'sent' | 'failed' | 'not_supported'; httpStatus?: number }> }

const STATUS = { sent: '앱에 알림', failed: '알림 실패', not_supported: '앱에 알릴 수 없음' } as const

/** The apps that hold sign-in tokens for this person, and a way to sign them out of those apps. */
export function AppSessions({ id }: { id: string }) {
  const queryClient = useQueryClient()
  const query = useUserData<{ apps: AppSession[] }>(id, 'app-sessions')
  const [target, setTarget] = useState<AppSession | 'all' | null>(null)
  const [result, setResult] = useState<RevokeResult | null>(null)

  const revoke = useMutation({
    mutationFn: (clientId?: string) => apiFetch<RevokeResult>(`/api/admin/users/${id}/app-sessions/revoke`, { method: 'POST', body: JSON.stringify(clientId ? { clientId } : {}) }),
    onSuccess: async (outcome) => {
      setResult(outcome)
      setTarget(null)
      toast.success('앱 로그인 상태를 끝냈습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'users', 'detail', id] })
    },
    onError: () => {
      setTarget(null)
      toast.error('처리하지 못했습니다.')
    },
  })

  if (query.isPending) return <Loading />
  if (query.error) return <Failed what="앱 로그인 상태" />
  const apps = query.data.apps

  return (
    <Panel
      title="앱 로그인 상태"
      description="앱이 이 사용자의 이름으로 받아 둔 토큰입니다. 끝내면 토큰이 폐기되고, 앱이 로그아웃 주소를 등록해 두었다면 앱에도 알립니다. SAML 앱은 앱 쪽 세션을 끝낼 방법이 없습니다."
      action={
        <Button variant="outline" size="sm" disabled={apps.length === 0 || revoke.isPending} onClick={() => setTarget('all')}>
          <LogOutIcon data-icon="inline-start" />
          모든 앱에서 로그아웃
        </Button>
      }
    >
      {apps.length === 0 ? (
        <Nothing>토큰을 가진 앱이 없습니다.</Nothing>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>앱</TableHead>
                <TableHead>유효한 토큰</TableHead>
                <TableHead>마지막 발급</TableHead>
                <TableHead>앱에 알림</TableHead>
                <TableHead className="w-28" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {apps.map((app) => (
                <TableRow key={app.clientId}>
                  <TableCell className="font-medium">{app.applicationName}</TableCell>
                  <TableCell className="tabular-nums">{app.activeTokens}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{app.lastIssuedAt ? formatDateTime(app.lastIssuedAt) : '—'}</TableCell>
                  <TableCell>{app.backchannelLogout ? <Badge variant="secondary">가능</Badge> : <Badge variant="outline">없음</Badge>}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="outline" size="sm" disabled={revoke.isPending} onClick={() => setTarget(app)}>
                      로그아웃
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {result ? (
        <Alert>
          <AlertDescription>
            토큰 {result.revokedTokens}개를 폐기했습니다.
            {result.apps.length ? ` ${result.apps.map((entry) => `${entry.applicationName}: ${STATUS[entry.status]}`).join(' · ')}` : ''}
          </AlertDescription>
        </Alert>
      ) : null}
      <AlertDialog open={target !== null} onOpenChange={(open) => !open && !revoke.isPending && setTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{target === 'all' ? '모든 앱에서 로그아웃할까요?' : `${target?.applicationName}에서 로그아웃할까요?`}</AlertDialogTitle>
            <AlertDialogDescription>이 사용자가 앱에 로그인해 둔 상태가 끝나 다음에 앱을 열 때 다시 로그인해야 합니다. 이 시스템의 로그인 세션은 그대로입니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={revoke.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={revoke.isPending} onClick={(event) => { event.preventDefault(); revoke.mutate(target && target !== 'all' ? target.clientId : undefined) }}>
              로그아웃
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Panel>
  )
}
