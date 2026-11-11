import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { ApiError, apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type View = {
  configured: boolean
  enabled: boolean
  baseUrlHost: string | null
  tokenSet: boolean
  lastTestAt: string | null
  lastTestOk: boolean | null
  counts: { pending: number; in_progress: number; succeeded: number; failed: number; outcome_unknown: number }
  lastSyncAt: string | null
  canStoreSecrets: boolean
}

const COUNT_LABELS: Array<[keyof View['counts'], string]> = [
  ['succeeded', '성공'],
  ['failed', '실패'],
  ['pending', '대기'],
  ['in_progress', '진행 중'],
  ['outcome_unknown', '결과 불명'],
]

const message = (error: unknown, fallback: string) => (error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : fallback)

/** Where this app's users are pushed to, as a SCIM 2.0 server, and a way to try it. */
export function ProvisioningPanel({ slug }: { slug: string }) {
  const queryClient = useQueryClient()
  const key = ['admin', 'application', slug, 'provisioning']
  const query = useQuery({ queryKey: key, queryFn: () => apiFetch<View>(`/api/admin/applications/${slug}/provisioning`) })
  if (query.isPending) return <Skeleton className="h-64 w-full" />
  if (query.error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>프로비저닝 설정을 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  return <Body key={JSON.stringify([query.data.baseUrlHost, query.data.enabled, query.data.tokenSet])} slug={slug} view={query.data} refresh={() => queryClient.invalidateQueries({ queryKey: key })} />
}

function Body({ slug, view, refresh }: { slug: string; view: View; refresh: () => Promise<unknown> }) {
  const [baseUrl, setBaseUrl] = useState(view.baseUrlHost ? `https://${view.baseUrlHost}` : '')
  const [token, setToken] = useState('')
  const [enabled, setEnabled] = useState(view.enabled)
  const [failure, setFailure] = useState<string | null>(null)
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null)
  const [removing, setRemoving] = useState(false)

  const save = useMutation({
    mutationFn: () => apiFetch(`/api/admin/applications/${slug}/provisioning`, { method: 'PUT', body: JSON.stringify({ baseUrl: baseUrl.trim(), ...(token ? { bearerToken: token } : {}), enabled }) }),
    onSuccess: async () => {
      setFailure(null)
      setToken('')
      toast.success('저장했습니다.')
      await refresh()
    },
    onError: (error) => setFailure(message(error, '저장하지 못했습니다.')),
  })
  const test = useMutation({
    mutationFn: () => apiFetch<{ ok: boolean; httpStatus?: number; error?: string }>(`/api/admin/applications/${slug}/provisioning/test`, { method: 'POST', body: '{}' }),
    onSuccess: async (outcome) => {
      setResult(outcome.ok ? { ok: true, text: `연결했습니다. (HTTP ${outcome.httpStatus ?? 200})` } : { ok: false, text: outcome.error ?? '연결하지 못했습니다.' })
      await refresh()
    },
    onError: (error) => setResult({ ok: false, text: message(error, '연결하지 못했습니다.') }),
  })
  const sync = useMutation({
    mutationFn: () => apiFetch<{ processed: number; succeeded: number; failed: number; remaining: number }>(`/api/admin/applications/${slug}/provisioning/sync`, { method: 'POST', body: '{}' }),
    onSuccess: async (outcome) => {
      setResult({
        ok: outcome.failed === 0,
        text: `${outcome.processed}명 처리: 성공 ${outcome.succeeded}, 실패 ${outcome.failed}.${outcome.remaining ? ` 아직 ${outcome.remaining}명이 남았습니다. 다시 누르세요.` : ''}`,
      })
      await refresh()
    },
    onError: (error) => setResult({ ok: false, text: message(error, '동기화하지 못했습니다.') }),
  })
  const remove = useMutation({
    mutationFn: () => apiFetch(`/api/admin/applications/${slug}/provisioning`, { method: 'DELETE' }),
    onSuccess: async () => {
      setRemoving(false)
      toast.success('연결을 지웠습니다.')
      await refresh()
    },
    onError: () => toast.error('지우지 못했습니다.'),
  })

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-xl text-sm text-muted-foreground">이 앱을 열 수 있는 사람들을 앱의 SCIM 2.0 서버에 만들고 갱신하고, 더는 열 수 없게 되면 비활성화합니다.</p>
        <div className="flex items-center gap-2">
          <Badge variant={view.configured ? (view.enabled ? 'default' : 'secondary') : 'outline'}>{view.configured ? (view.enabled ? '사용 중' : '꺼짐') : '연결 안 됨'}</Badge>
          {view.lastTestAt ? <Badge variant={view.lastTestOk ? 'secondary' : 'destructive'}>테스트 {view.lastTestOk ? '성공' : '실패'}</Badge> : null}
        </div>
      </div>

      {!view.canStoreSecrets ? (
        <Alert variant="destructive">
          <AlertDescription>서버에 AEAD_SEALING_KEY가 없어 토큰을 저장할 수 없습니다. 배포 설정에 키를 넣은 뒤 이용하세요.</AlertDescription>
        </Alert>
      ) : null}

      <section className="flex flex-col gap-4 rounded-2xl border bg-card p-6">
        <Field>
          <FieldLabel htmlFor="prov-url">SCIM 서버 주소</FieldLabel>
          <Input id="prov-url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://app.example.com/scim/v2" autoComplete="off" spellCheck={false} />
          <FieldDescription>https 주소만 쓸 수 있습니다. 내부망 주소는 받지 않습니다.</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="prov-token">Bearer 토큰</FieldLabel>
          <Input id="prov-token" type="password" autoComplete="new-password" value={token} onChange={(event) => setToken(event.target.value)} placeholder={view.tokenSet ? '저장되어 있습니다. 바꾸려면 새 값을 입력' : 'SCIM 서버가 준 토큰'} />
        </Field>
        <Field orientation="horizontal">
          <Switch id="prov-enabled" checked={enabled} onCheckedChange={setEnabled} />
          <FieldLabel htmlFor="prov-enabled">사용</FieldLabel>
        </Field>
        {failure ? (
          <Alert variant="destructive">
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={save.isPending || !baseUrl.trim() || (!view.tokenSet && !token)} onClick={() => { setFailure(null); save.mutate() }}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
          {view.configured ? (
            <Button variant="outline" onClick={() => setRemoving(true)}>
              연결 지우기
            </Button>
          ) : null}
        </div>
      </section>

      {view.configured ? (
        <section className="flex flex-col gap-4 rounded-2xl border bg-card p-6">
          <h3 className="text-sm font-semibold">연결 확인과 동기화</h3>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" disabled={test.isPending} onClick={() => { setResult(null); test.mutate() }}>
              {test.isPending ? <Spinner data-icon="inline-start" /> : null}
              연결 테스트
            </Button>
            <Button variant="outline" disabled={sync.isPending || !view.enabled} title={view.enabled ? undefined : '먼저 사용을 켜고 저장하세요'} onClick={() => { setResult(null); sync.mutate() }}>
              {sync.isPending ? <Spinner data-icon="inline-start" /> : null}
              지금 동기화
            </Button>
          </div>
          {result ? (
            <Alert variant={result.ok ? 'default' : 'destructive'}>
              <AlertDescription className="break-all">{result.text}</AlertDescription>
            </Alert>
          ) : null}
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            {COUNT_LABELS.map(([countKey, label]) => (
              <span key={countKey}>
                {label} {view.counts[countKey]}
              </span>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            {view.lastTestAt ? `마지막 테스트 ${formatDateTime(view.lastTestAt)}. ` : ''}
            {view.lastSyncAt ? `마지막 동기화 ${formatDateTime(view.lastSyncAt)}. ` : '아직 동기화한 적이 없습니다. '}
            자세한 기록은 <Link to="/admin/integrations" className="underline">연동 화면</Link>에서 봅니다.
          </p>
        </section>
      ) : null}

      <AlertDialog open={removing} onOpenChange={(open) => !open && !remove.isPending && setRemoving(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>이 앱의 프로비저닝 연결을 지울까요?</AlertDialogTitle>
            <AlertDialogDescription>주소와 토큰이 삭제되고 더는 사용자가 앱으로 전달되지 않습니다. 이미 앱에 만들어진 계정은 그대로 남습니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={remove.isPending} onClick={(event) => { event.preventDefault(); remove.mutate() }}>
              지우기
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
