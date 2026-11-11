import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Field, FieldContent, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type Kind = 'email' | 'sms'
type FieldSpec = {
  key: string
  label: string
  secret?: boolean
  required?: boolean
  placeholder?: string
  help?: string
  type?: 'text' | 'number' | 'select'
  options?: Array<{ value: string; label: string }>
}
type ProviderSpec = { id: string; label: string; description: string; fields: FieldSpec[] }
type KindView = {
  source: 'console' | 'deployment' | 'none'
  provider: string | null
  values: Record<string, string>
  secretsSet: Record<string, boolean>
  available: boolean
  updatedAt: string | null
}
type DeliveryView = {
  email: KindView
  sms: KindView
  catalog: { email: ProviderSpec[]; sms: ProviderSpec[]; common: Record<Kind, FieldSpec[]> }
  canStoreSecrets: boolean
}

const COPY: Record<Kind, { title: string; description: string; testLabel: string; testPlaceholder: string }> = {
  email: { title: '이메일', description: '비밀번호 설정 링크, 인증 코드 메일을 보내는 방법입니다.', testLabel: '받을 이메일', testPlaceholder: 'me@example.com' },
  sms: { title: '문자(SMS)', description: '휴대전화로 보내는 인증 코드를 보내는 방법입니다.', testLabel: '받을 번호', testPlaceholder: '+821012345678' },
}

const SOURCES = {
  console: { label: '콘솔 설정', variant: 'default' },
  deployment: { label: '서버 환경변수', variant: 'secondary' },
  none: { label: '설정 안 됨', variant: 'outline' },
} as const

/** How e-mail and SMS leave the system: the provider, its keys, and a test message. */
export function DeliveryPage() {
  const query = useQuery({ queryKey: ['admin', 'delivery'], queryFn: () => apiFetch<DeliveryView>('/api/admin/delivery') })
  if (query.isPending) {
    return (
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-4">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }
  if (query.error) {
    return (
      <div className="mx-auto w-full max-w-4xl">
        <Alert variant="destructive">
          <AlertDescription>발송 설정을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      </div>
    )
  }
  const view = query.data
  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">메시지 발송</h1>
        <p className="text-sm text-muted-foreground">이메일과 문자를 어느 서비스로 보낼지 정합니다. 여기서 저장하면 서버 환경변수보다 우선합니다.</p>
      </div>
      {!view.canStoreSecrets ? (
        <Alert variant="destructive">
          <AlertDescription>서버에 AEAD_SEALING_KEY가 설정되어 있지 않아 API 키 같은 비밀값은 저장할 수 없습니다. 배포 설정에 키를 넣은 뒤 이용하세요.</AlertDescription>
        </Alert>
      ) : null}
      {(['email', 'sms'] as const).map((kind) => (
        <KindCard key={`${kind}-${view[kind].updatedAt}-${view[kind].provider}-${view[kind].source}`} kind={kind} view={view} />
      ))}
    </div>
  )
}

function KindCard({ kind, view }: { kind: Kind; view: DeliveryView }) {
  const queryClient = useQueryClient()
  const current = view[kind]
  const providers = view.catalog[kind]
  const [provider, setProvider] = useState(current.provider && providers.some((p) => p.id === current.provider) ? current.provider : providers[0]!.id)
  const [values, setValues] = useState<Record<string, string>>(current.provider === provider ? current.values : {})
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const [failure, setFailure] = useState<string | null>(null)
  const [testTo, setTestTo] = useState('')
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null)
  const [resetting, setResetting] = useState(false)

  const spec = providers.find((p) => p.id === provider)!
  const fields = [...view.catalog.common[kind], ...spec.fields]
  const stored = current.source === 'console' && current.provider === provider
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'delivery'] })

  const save = useMutation({
    mutationFn: () => {
      // A secret left empty is not sent, so what is stored stays.
      const sent = Object.fromEntries(Object.entries(secrets).filter(([, value]) => value !== ''))
      return apiFetch(`/api/admin/delivery/${kind}`, { method: 'PUT', body: JSON.stringify({ provider, values, secrets: sent }) })
    },
    onSuccess: async () => {
      setFailure(null)
      toast.success('저장했습니다.')
      await refresh()
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })
  const reset = useMutation({
    mutationFn: () => apiFetch(`/api/admin/delivery/${kind}`, { method: 'DELETE' }),
    onSuccess: async () => {
      setResetting(false)
      toast.success('서버 환경변수 설정으로 되돌렸습니다.')
      await refresh()
    },
    onError: () => toast.error('되돌리지 못했습니다.'),
  })
  const test = useMutation({
    mutationFn: () => apiFetch<{ ok: boolean; error?: string }>(`/api/admin/delivery/${kind}/test`, { method: 'POST', body: JSON.stringify({ to: testTo.trim() }) }),
    onSuccess: (result) => setTestResult(result.ok ? { ok: true, text: '보냈습니다. 받은편지함이나 휴대전화를 확인하세요.' } : { ok: false, text: result.error ?? '보내지 못했습니다.' }),
    onError: (error) => setTestResult({ ok: false, text: error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '보내지 못했습니다.' }),
  })

  function change(next: string) {
    setProvider(next)
    setValues(current.provider === next ? current.values : {})
    setSecrets({})
    setFailure(null)
  }

  const copy = COPY[kind]
  const source = SOURCES[current.source]
  return (
    <section className="flex flex-col gap-6 rounded-2xl border bg-card p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold">{copy.title}</h2>
          <p className="text-xs text-muted-foreground">{copy.description}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={source.variant}>{source.label}</Badge>
          {current.source !== 'none' ? <Badge variant={current.available ? 'secondary' : 'destructive'}>{current.available ? '보낼 수 있음' : '키가 부족함'}</Badge> : null}
        </div>
      </div>
      {current.source === 'deployment' ? (
        <Alert>
          <AlertDescription>지금은 서버 환경변수로 {current.provider} 공급자를 쓰고 있습니다. 아래에서 저장하면 콘솔 설정이 우선합니다.</AlertDescription>
        </Alert>
      ) : null}

      <div className="flex flex-col gap-3">
        <h3 className="text-xs font-medium text-muted-foreground">공급자</h3>
        <RadioGroup value={provider} onValueChange={change}>
          {providers.map((entry) => (
            <Field key={entry.id} orientation="horizontal">
              <RadioGroupItem id={`${kind}-${entry.id}`} value={entry.id} />
              <FieldContent>
                <FieldLabel htmlFor={`${kind}-${entry.id}`}>{entry.label}</FieldLabel>
                <FieldDescription>{entry.description}</FieldDescription>
              </FieldContent>
            </Field>
          ))}
        </RadioGroup>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {fields.map((field) => {
          const id = `${kind}-field-${field.key}`
          const isSet = field.secret && stored && current.secretsSet[field.key]
          return (
            <Field key={field.key}>
              <FieldLabel htmlFor={id}>
                {field.label}
                {field.required ? <span className="text-destructive"> *</span> : null}
              </FieldLabel>
              {field.type === 'select' ? (
                <Select value={values[field.key] || field.options![0]!.value} onValueChange={(value) => setValues({ ...values, [field.key]: value })}>
                  <SelectTrigger id={id}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {field.options!.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              ) : field.secret ? (
                <Input
                  id={id}
                  type="password"
                  autoComplete="new-password"
                  placeholder={isSet ? '저장되어 있습니다. 바꾸려면 새 값을 입력' : field.placeholder}
                  value={secrets[field.key] ?? ''}
                  onChange={(event) => setSecrets({ ...secrets, [field.key]: event.target.value })}
                />
              ) : (
                <Input
                  id={id}
                  inputMode={field.type === 'number' ? 'numeric' : undefined}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={field.placeholder}
                  value={values[field.key] ?? ''}
                  onChange={(event) => setValues({ ...values, [field.key]: event.target.value })}
                />
              )}
              {field.help ? <FieldDescription>{field.help}</FieldDescription> : null}
            </Field>
          )
        })}
      </div>

      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <div className="flex flex-wrap items-center gap-3">
        <Button disabled={save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? <Spinner data-icon="inline-start" /> : null}
          저장
        </Button>
        {current.source === 'console' ? (
          <Button variant="ghost" onClick={() => setResetting(true)}>
            서버 설정으로 되돌리기
          </Button>
        ) : null}
        {current.updatedAt ? <span className="text-xs text-muted-foreground">마지막 저장 {formatDateTime(current.updatedAt)}</span> : null}
      </div>

      <div className="flex flex-col gap-3 border-t pt-5">
        <h3 className="text-xs font-medium text-muted-foreground">테스트 발송</h3>
        <p className="text-xs text-muted-foreground">지금 저장된 설정으로 실제 메시지를 한 통 보냅니다. 입력만 하고 저장하지 않은 값은 쓰이지 않습니다.</p>
        <div className="flex flex-wrap items-center gap-2">
          <Input aria-label={copy.testLabel} className="w-64" placeholder={copy.testPlaceholder} value={testTo} onChange={(event) => setTestTo(event.target.value)} />
          <Button variant="outline" disabled={test.isPending || !testTo.trim() || current.source === 'none'} onClick={() => { setTestResult(null); test.mutate() }}>
            {test.isPending ? <Spinner data-icon="inline-start" /> : null}
            테스트 보내기
          </Button>
        </div>
        {testResult ? (
          <Alert variant={testResult.ok ? 'default' : 'destructive'}>
            <AlertDescription className="break-all">{testResult.text}</AlertDescription>
          </Alert>
        ) : null}
      </div>

      <AlertDialog open={resetting} onOpenChange={(open) => !open && !reset.isPending && setResetting(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>콘솔 설정을 지우고 서버 설정으로 되돌릴까요?</AlertDialogTitle>
            <AlertDialogDescription>저장한 공급자와 키가 삭제됩니다. 서버 환경변수에 설정이 없으면 {copy.title}을(를) 보낼 수 없게 됩니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={reset.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={reset.isPending} onClick={(event) => { event.preventDefault(); reset.mutate() }}>
              되돌리기
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  )
}
