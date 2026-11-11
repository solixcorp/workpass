import { useMutation } from '@tanstack/react-query'
import { CheckCircle2Icon, XCircleIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { ScopeList } from './approval-card'

type Pending = { client_name: string; scopes: string[]; expires_in: number }

/** Enter the code a device shows, see what it asks for, then approve or deny. */
export function DevicePage() {
  const initial = new URLSearchParams(window.location.search).get('user_code') ?? ''
  const [code, setCode] = useState(initial.toUpperCase())
  const [pending, setPending] = useState<(Pending & { code: string }) | null>(null)
  const [outcome, setOutcome] = useState<'approved' | 'denied' | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  const lookup = useMutation({
    mutationFn: (value: string) => apiFetch<Pending>('/api/device/flow/verify', { method: 'POST', body: JSON.stringify({ user_code: value }) }),
    onSuccess: (data, value) => setPending({ ...data, code: value }),
    onError: (error) =>
      setFailure(
        error instanceof ApiError && error.status === 409
          ? '이미 처리된 요청입니다.'
          : '코드를 찾을 수 없거나 만료되었습니다. 기기에 표시된 코드를 다시 확인하세요.',
      ),
  })
  const decide = useMutation({
    mutationFn: (approve: boolean) =>
      apiFetch<{ status: 'approved' | 'denied' }>(`/api/device/flow/${approve ? 'approve' : 'deny'}`, { method: 'POST', body: JSON.stringify({ user_code: pending!.code }) }),
    onSuccess: (data) => setOutcome(data.status),
    onError: () => setFailure('처리하지 못했습니다. 요청이 만료되었을 수 있습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    if (code.trim()) lookup.mutate(code.trim())
  }

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">기기 로그인</h1>
        <p className="text-sm text-muted-foreground">TV나 터미널처럼 입력하기 어려운 기기에서 내 계정으로 로그인합니다.</p>
      </div>

      {outcome ? (
        <div className="flex flex-col items-center gap-3 rounded-2xl border bg-card p-8 text-center">
          {outcome === 'approved' ? <CheckCircle2Icon className="size-10 text-primary" /> : <XCircleIcon className="size-10 text-muted-foreground" />}
          <p className="text-sm font-medium">{outcome === 'approved' ? '승인했습니다. 기기로 돌아가세요.' : '거절했습니다.'}</p>
        </div>
      ) : pending ? (
        <div className="flex flex-col gap-5 rounded-2xl border bg-card p-6">
          <p className="text-sm">
            기기 <strong>{pending.client_name}</strong>이(가) 접근을 요청합니다.
          </p>
          <section className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold">요청하는 권한</h2>
            <ScopeList scopes={pending.scopes} />
          </section>
          <p className="text-xs text-muted-foreground">내가 방금 연 기기가 아니라면 거절하세요.</p>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <div className="flex gap-2">
            <Button disabled={decide.isPending} onClick={() => { setFailure(null); decide.mutate(true) }}>
              {decide.isPending ? <Spinner data-icon="inline-start" /> : null}
              승인
            </Button>
            <Button variant="outline" disabled={decide.isPending} onClick={() => { setFailure(null); decide.mutate(false) }}>
              거절
            </Button>
          </div>
        </div>
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-4 rounded-2xl border bg-card p-6" autoComplete="off">
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="device-code">기기 코드</FieldLabel>
              <Input id="device-code" className="font-mono uppercase tracking-widest" value={code} onChange={(event) => setCode(event.target.value.toUpperCase())} maxLength={16} autoFocus />
              <FieldDescription>기기 화면에 표시된 코드를 입력하세요. 코드는 10분 뒤 만료됩니다.</FieldDescription>
            </Field>
          </FieldGroup>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <div>
            <Button type="submit" disabled={lookup.isPending || !code.trim()}>
              {lookup.isPending ? <Spinner data-icon="inline-start" /> : null}
              계속
            </Button>
          </div>
        </form>
      )}
    </div>
  )
}
