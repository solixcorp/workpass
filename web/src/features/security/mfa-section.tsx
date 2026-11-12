import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckIcon, CopyIcon, PlusIcon, ShieldCheckIcon, Trash2Icon } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp'
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemTitle,
} from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { opaqueConfirmPassword } from '@/lib/opaque'
import { formatDateTime } from '@/lib/format'
import { enrollmentKey, enrollmentQuery, type EnrollmentView } from '@/lib/mfa'
import { TwoFactorForm } from '@/features/auth/two-factor-form'

type Flow =
  | { kind: 'totp' }
  | { kind: 'otp' }
  | { kind: 'hotp' }
  | { kind: 'backup' }
  | { kind: 'disable' }
  | null

function message(error: { message?: string } | null | undefined, fallback: string) {
  return error?.message && /[가-힣]/.test(error.message) ? error.message : fallback
}

export function MfaSection() {
  const { data, isPending, error } = useQuery(enrollmentQuery)
  const [flow, setFlow] = useState<Flow>(null)

  if (error) {
    return (
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-muted-foreground">2차 인증</h2>
        <Alert variant="destructive">
          <AlertDescription>2차 인증 정보를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      </section>
    )
  }
  if (isPending) return <Skeleton className="h-48 rounded-xl" />

  const open = (key: string) => {
    if (key === 'totp' || key === 'otp' || key === 'hotp') setFlow({ kind: key })
  }

  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <h2 className="text-sm font-medium text-muted-foreground">{data.title}</h2>
        <p className="text-sm text-muted-foreground">{data.description}</p>
      </div>
      {data.mustEnroll ? (
        <Alert>
          <ShieldCheckIcon />
          <AlertDescription>{data.requiredNotice}</AlertDescription>
        </Alert>
      ) : null}
      <ItemGroup className="gap-2">
        {data.methods.map((method) => (
          <Item key={method.key} variant="outline">
            <ItemContent>
              <ItemTitle>
                {method.label}
                <Badge variant={method.state === 'enrolled' ? 'secondary' : 'outline'}>
                  {method.stateLabel}
                </Badge>
              </ItemTitle>
              <ItemDescription>{method.description}</ItemDescription>
            </ItemContent>
            <ItemActions>
              {method.actions.includes('enroll') || method.actions.includes('add') ? (
                <Button variant="outline" size="sm" onClick={() => open(method.key)}>
                  <PlusIcon data-icon="inline-start" />
                  {method.actions.includes('add') ? data.labels.add : data.labels.enroll}
                </Button>
              ) : null}
            </ItemActions>
          </Item>
        ))}
      </ItemGroup>

      {data.hotpTokens.length > 0 ? (
        <ItemGroup className="gap-2">
          {data.hotpTokens.map((token) => (
            <HotpTokenRow key={token.id} id={token.id} label={token.label} createdAt={token.createdAt} verified={token.verified} removeLabel={data.labels.remove} />
          ))}
        </ItemGroup>
      ) : null}

      {data.backupCodes.available || data.disable.available || data.disable.blockedReason ? (
        <div className="flex flex-wrap items-center gap-2">
          {data.backupCodes.available ? (
            <Button variant="outline" size="sm" onClick={() => setFlow({ kind: 'backup' })}>
              {data.backupCodes.label}
            </Button>
          ) : null}
          {data.disable.available ? (
            <Button variant="outline" size="sm" onClick={() => setFlow({ kind: 'disable' })}>
              {data.disable.label}
            </Button>
          ) : null}
          {data.disable.blockedReason ? (
            <span className="text-sm text-muted-foreground">{data.disable.blockedReason}</span>
          ) : null}
        </div>
      ) : null}

      <EnrollmentDialogs view={data} kind={flow?.kind === 'totp' || flow?.kind === 'otp' || flow?.kind === 'hotp' ? flow.kind : null} onClose={() => setFlow(null)} />
      <BackupDialog view={data} open={flow?.kind === 'backup'} onClose={() => setFlow(null)} />
      <DisableDialog view={data} open={flow?.kind === 'disable'} onClose={() => setFlow(null)} />
    </section>
  )
}

/** The enrollment dialogs on their own, for screens that open one method at a time (the sign-in card). */
export function EnrollmentDialogs({
  view,
  kind,
  onClose,
}: {
  view: EnrollmentView
  kind: 'totp' | 'otp' | 'hotp' | null
  onClose: () => void
}) {
  if (view.verification.required) {
    return <VerificationDialog view={view} open={kind !== null} onClose={onClose} />
  }
  return (
    <>
      <TotpDialog view={view} open={kind === 'totp'} onClose={onClose} />
      <OtpDialog view={view} open={kind === 'otp'} onClose={onClose} />
      <HotpDialog view={view} open={kind === 'hotp'} onClose={onClose} />
    </>
  )
}

/** Adding a factor needs the password again and a second check: an existing method, or an emailed code when there is none. */
function VerificationDialog({ view, open, onClose }: { view: EnrollmentView; open: boolean; onClose: () => void }) {
  const refresh = useRefresh()
  const [selected, setSelected] = useState<string | null>(null)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [sent, setSent] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { ui, blockedReason, steps } = view.verification
  const method = ui.methods.find((entry) => entry.key === selected) ?? null

  function close() {
    setSelected(null)
    setPassword('')
    setCode('')
    setSent(false)
    setError(null)
    onClose()
  }

  async function confirmPassword(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    const result = await opaqueConfirmPassword(password)
    setPending(false)
    setPassword('')
    if (result === 'ok') {
      await refresh()
      return
    }
    setError(
      result === 'invalid'
        ? '비밀번호가 올바르지 않습니다.'
        : result === 'rate_limited'
          ? '시도가 너무 많습니다. 잠시 후 다시 시도하세요.'
          : result === 'no_password'
            ? '이 계정에는 확인할 비밀번호가 없습니다. 관리자에게 문의하세요.'
            : '확인하지 못했습니다. 잠시 후 다시 시도하세요.',
    )
  }

  async function sendCode() {
    setError(null)
    setPending(true)
    try {
      await apiFetch('/api/mfa/gate/code/start', { method: 'POST' })
      setSent(true)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : '코드를 보내지 못했습니다.')
    }
    setPending(false)
  }

  async function confirmCode(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      await apiFetch('/api/mfa/gate/code/confirm', { method: 'POST', body: JSON.stringify({ code }) })
      setCode('')
      setSent(false)
      await refresh()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : '확인하지 못했습니다.')
    }
    setPending(false)
  }

  const step = !steps.passwordOk ? 'password' : !steps.secondOk ? 'second' : 'done'

  return (
    <Dialog open={open} onOpenChange={(next) => !next && close()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{ui.title}</DialogTitle>
          <DialogDescription>
            {step === 'password'
              ? '1/2 계정 비밀번호를 다시 입력하세요.'
              : steps.secondMode === 'email'
                ? '2/2 계정 이메일로 보낸 코드를 입력하세요.'
                : '2/2 이미 등록한 인증 수단 중 하나로 확인하세요.'}
          </DialogDescription>
        </DialogHeader>
        {blockedReason ? (
          <>
            <Alert><AlertDescription>{blockedReason}</AlertDescription></Alert>
            <DialogFooter><Button variant="outline" onClick={close}>닫기</Button></DialogFooter>
          </>
        ) : step === 'password' ? (
          <form onSubmit={confirmPassword} className="flex flex-col gap-4">
            <FieldGroup>
              <Field data-invalid={error ? true : undefined}>
                <FieldLabel htmlFor="mfa-gate-password">계정 비밀번호</FieldLabel>
                <Input
                  id="mfa-gate-password"
                  type="password"
                  autoComplete="current-password"
                  autoFocus
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
                {error ? <FieldError>{error}</FieldError> : null}
              </Field>
            </FieldGroup>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close}>취소</Button>
              <Button type="submit" disabled={pending || !password}>
                {pending ? <Spinner data-icon="inline-start" /> : null}
                확인
              </Button>
            </DialogFooter>
          </form>
        ) : steps.secondMode === 'email' ? (
          sent ? (
            <form onSubmit={confirmCode} className="flex flex-col gap-4">
              <FieldGroup>
                <Field data-invalid={error ? true : undefined}>
                  <FieldLabel htmlFor="mfa-gate-code">확인 코드</FieldLabel>
                  <CodeInput id="mfa-gate-code" value={code} onChange={setCode} />
                  <FieldDescription>10분 안에 입력하세요.</FieldDescription>
                  {error ? <FieldError>{error}</FieldError> : null}
                </Field>
              </FieldGroup>
              <DialogFooter>
                <Button type="button" variant="outline" disabled={pending} onClick={sendCode}>다시 보내기</Button>
                <Button type="submit" disabled={pending || code.length !== 6}>
                  {pending ? <Spinner data-icon="inline-start" /> : null}
                  확인
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <div className="flex flex-col gap-4">
              <p className="text-sm text-muted-foreground">등록된 인증 수단이 아직 없어서, 계정 이메일로 확인 코드를 보냅니다.</p>
              {error ? <FieldError>{error}</FieldError> : null}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={close}>취소</Button>
                <Button type="button" disabled={pending} onClick={sendCode}>
                  {pending ? <Spinner data-icon="inline-start" /> : null}
                  코드 보내기
                </Button>
              </DialogFooter>
            </div>
          )
        ) : method ? (
          <TwoFactorForm
            key={method.key}
            ui={{ ...ui, methods: [method], alternatives: [{ label: '다른 방법 선택', action: 'cancel' }] }}
            onVerified={async () => {
              setSelected(null)
              await refresh()
            }}
            onCancel={() => setSelected(null)}
          />
        ) : (
          <div className="flex flex-col gap-2">
            {ui.methods.map((item) => (
              <Button
                key={item.key}
                type="button"
                variant="outline"
                className="h-auto justify-start px-3 py-2.5 text-left"
                onClick={() => setSelected(item.key)}
              >
                <span className="flex flex-col items-start gap-0.5">
                  <span className="text-sm font-medium">{item.label}</span>
                  {item.description ? (
                    <span className="text-xs font-normal text-muted-foreground">{item.description}</span>
                  ) : null}
                </span>
              </Button>
            ))}
            <Button type="button" variant="ghost" className="text-muted-foreground" onClick={close}>
              {ui.alternatives[0]?.label}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function HotpTokenRow({
  id,
  label,
  createdAt,
  verified,
  removeLabel,
}: {
  id: string
  label: string
  createdAt: string
  verified: boolean
  removeLabel: string
}) {
  const queryClient = useQueryClient()
  const [verifyOpen, setVerifyOpen] = useState(false)
  const [code, setCode] = useState('')
  const [verifyError, setVerifyError] = useState<string | null>(null)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const verify = useMutation({
    mutationFn: () => apiFetch('/api/mfa/hotp/verify', { method: 'POST', body: JSON.stringify({ tokenId: id, code }) }),
    onSuccess: () => {
      toast.success('토큰을 인증했습니다.')
      setVerifyOpen(false)
      setCode('')
      setVerifyError(null)
      return queryClient.invalidateQueries({ queryKey: enrollmentKey })
    },
    onError: () => setVerifyError('코드가 올바르지 않습니다. 토큰의 새 코드를 입력하세요.'),
  })
  const remove = useMutation({
    mutationFn: () => apiFetch(`/api/mfa/hotp/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      toast.success('토큰을 삭제했습니다.')
      return queryClient.invalidateQueries({ queryKey: enrollmentKey })
    },
    onError: (cause: unknown) =>
      toast.error(cause instanceof ApiError ? cause.message : '토큰을 삭제하지 못했습니다.'),
    onSettled: () => setConfirmRemove(false),
  })
  return (
    <Item variant="muted" size="sm">
      <ItemContent>
        <ItemTitle>{label}{verified ? null : <Badge variant="outline">확인 대기</Badge>}</ItemTitle>
        <ItemDescription>{formatDateTime(createdAt)}</ItemDescription>
      </ItemContent>
      <ItemActions>
        {!verified ? <Button variant="outline" size="sm" onClick={() => setVerifyOpen(true)}>인증 계속</Button> : null}
        <Button variant="ghost" size="icon-sm" aria-label={`${label} ${removeLabel}`} disabled={remove.isPending} onClick={() => setConfirmRemove(true)}>
          <Trash2Icon />
        </Button>
      </ItemActions>
      <ConfirmDialog
        open={confirmRemove}
        title="이 보안 토큰을 삭제할까요?"
        description="삭제하면 이 토큰의 코드로는 더 이상 추가 인증을 할 수 없고, 되돌릴 수 없습니다. 이름과 등록일이 맞는지 확인하세요."
        details={[{ label: '이름', value: label }, { label: '등록일', value: formatDateTime(createdAt) }, { label: '상태', value: verified ? '인증됨' : '확인 대기' }]}
        confirmLabel="삭제"
        pending={remove.isPending}
        onConfirm={() => remove.mutate()}
        onCancel={() => setConfirmRemove(false)}
      />
      <Dialog open={verifyOpen} onOpenChange={(next) => !next && !verify.isPending && setVerifyOpen(false)}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader><DialogTitle>보안 토큰 확인</DialogTitle><DialogDescription>토큰의 새 코드를 입력하세요.</DialogDescription></DialogHeader>
          <Field data-invalid={verifyError ? true : undefined}>
            <FieldLabel htmlFor={`hotp-verify-${id}`}>인증 코드</FieldLabel>
            <CodeInput id={`hotp-verify-${id}`} value={code} onChange={(value) => { setCode(value); setVerifyError(null) }} />
            {verifyError ? <FieldError>{verifyError}</FieldError> : null}
          </Field>
          <DialogFooter><Button disabled={verify.isPending || code.length !== 6} onClick={() => verify.mutate()}>{verify.isPending ? <Spinner data-icon="inline-start" /> : null}확인</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </Item>
  )
}

/** Account password, asked only when the server says the account still holds one. */
function PasswordField({
  view,
  value,
  onChange,
}: {
  view: EnrollmentView
  value: string
  onChange: (value: string) => void
}) {
  if (!view.passwordRequired) return null
  return (
    <Field>
      <FieldLabel htmlFor="mfa-password">{view.passwordLabel}</FieldLabel>
      <Input
        id="mfa-password"
        type="password"
        autoComplete="current-password"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </Field>
  )
}

function CodeInput({ id, value, onChange }: { id: string; value: string; onChange: (value: string) => void }) {
  return (
    <InputOTP id={id} maxLength={6} value={value} onChange={onChange} autoComplete="one-time-code" inputMode="numeric" pattern="^[0-9]*$">
      <InputOTPGroup>
        {Array.from({ length: 6 }, (_, index) => (
          <InputOTPSlot key={index} index={index} />
        ))}
      </InputOTPGroup>
    </InputOTP>
  )
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        await navigator.clipboard.writeText(text).catch(() => undefined)
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      }}
    >
      {copied ? <CheckIcon data-icon="inline-start" /> : <CopyIcon data-icon="inline-start" />}
      {label}
    </Button>
  )
}

function BackupCodes({ view, codes }: { view: EnrollmentView; codes: string[] }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <p className="text-sm font-medium">{view.labels.backupTitle}</p>
        <p className="text-sm text-muted-foreground">{view.labels.backupBody}</p>
      </div>
      <ul className="grid grid-cols-2 gap-2 rounded-lg bg-muted p-3 font-mono text-sm">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div>
        <CopyButton text={codes.join('\n')} label={view.labels.copy} />
      </div>
    </div>
  )
}

function useRefresh() {
  const queryClient = useQueryClient()
  return async () => {
    await queryClient.invalidateQueries({ queryKey: enrollmentKey })
    await queryClient.invalidateQueries({ queryKey: ['step-up'] })
  }
}

function TotpDialog({ view, open, onClose }: { view: EnrollmentView; open: boolean; onClose: () => void }) {
  const refresh = useRefresh()
  const [password, setPassword] = useState('')
  const [setup, setSetup] = useState<{ uri: string; secret: string; codes: string[] } | null>(null)
  const [code, setCode] = useState('')
  const [finished, setFinished] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function close() {
    setPassword('')
    setSetup(null)
    setCode('')
    setFinished(false)
    setError(null)
    onClose()
  }

  async function start(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    const result = await authClient.twoFactor.enable({
      ...(view.passwordRequired ? { password } : {}),
    } as { password: string })
    setPending(false)
    const enrolled = result.data
    if (result.error || !enrolled || enrolled.method !== 'totp') {
      setError(message(result.error, '인증 앱 등록을 시작하지 못했습니다.'))
      if (result.error?.status === 403) await refresh()
      return
    }
    const secret = new URL(enrolled.totpURI).searchParams.get('secret') ?? ''
    setSetup({ uri: enrolled.totpURI, secret, codes: enrolled.backupCodes })
  }

  async function confirm(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    const result = await authClient.twoFactor.verifyTotp({ code })
    setPending(false)
    if (result.error) {
      setError('코드가 올바르지 않습니다. 앱에 표시된 최신 코드를 입력하세요.')
      setCode('')
      return
    }
    setFinished(true)
    await refresh()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !pending && close()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>인증 앱 등록</DialogTitle>
          <DialogDescription>
            {finished ? '등록을 마쳤습니다.' : setup ? view.labels.totpScan : '인증 앱을 쓰려면 먼저 등록을 시작하세요.'}
          </DialogDescription>
        </DialogHeader>

        {finished && setup ? (
          <BackupCodes view={view} codes={setup.codes} />
        ) : setup ? (
          <form id="mfa-totp-confirm" onSubmit={confirm} noValidate>
            <FieldGroup>
              <div className="flex justify-center rounded-lg bg-white p-4">
                <QRCodeSVG value={setup.uri} size={168} />
              </div>
              <Field>
                <FieldLabel>{view.labels.totpManual}</FieldLabel>
                <div className="flex items-center gap-2">
                  <code className="min-w-0 flex-1 truncate rounded-md bg-muted px-2 py-1.5 font-mono text-xs">{setup.secret}</code>
                  <CopyButton text={setup.secret} label={view.labels.copy} />
                </div>
              </Field>
              <Field data-invalid={error ? true : undefined}>
                <FieldLabel htmlFor="mfa-totp-code">{view.labels.totpVerify}</FieldLabel>
                <CodeInput id="mfa-totp-code" value={code} onChange={setCode} />
                {error ? <FieldError>{error}</FieldError> : null}
              </Field>
            </FieldGroup>
          </form>
        ) : (
          <form id="mfa-totp-start" onSubmit={start} noValidate>
            <FieldGroup>
              <PasswordField view={view} value={password} onChange={setPassword} />
              {error ? <FieldError>{error}</FieldError> : null}
            </FieldGroup>
          </form>
        )}

        <DialogFooter>
          {finished ? (
            <Button onClick={close}>{view.labels.done}</Button>
          ) : setup ? (
            <Button type="submit" form="mfa-totp-confirm" disabled={pending || code.length !== 6}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {view.labels.verify}
            </Button>
          ) : (
            <Button type="submit" form="mfa-totp-start" disabled={pending || (view.passwordRequired && !password)}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              시작
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function OtpDialog({ view, open, onClose }: { view: EnrollmentView; open: boolean; onClose: () => void }) {
  const refresh = useRefresh()
  const [password, setPassword] = useState('')
  const [step, setStep] = useState<1 | 2>(1)
  const [code, setCode] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function start(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      await apiFetch('/api/mfa/otp/start', { method: 'POST' })
      setStep(2)
    } catch (cause) {
      setError(message(cause instanceof ApiError ? cause : null, '인증 코드를 보내지 못했습니다.'))
      if (cause instanceof ApiError && cause.status === 403) await refresh()
    } finally {
      setPending(false)
    }
  }

  async function confirm(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      await apiFetch('/api/mfa/otp/confirm', { method: 'POST', body: JSON.stringify({ code, ...(view.passwordRequired ? { password } : {}) }) })
      toast.success(view.labels.otpEnabled)
      setPassword('')
      setCode('')
      await refresh()
      onClose()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 429) setError('시도 횟수를 넘었습니다. 처음부터 다시 시작하세요.')
      else if (cause instanceof ApiError && cause.status === 400) {
        setError('코드가 올바르지 않습니다. 최신 코드를 입력하세요.')
        setCode('')
      } else setError(message(cause instanceof ApiError ? cause : null, '일회용 코드를 켜지 못했습니다.'))
    } finally {
      setPending(false)
    }
  }

  function close() {
    setPassword('')
    setCode('')
    setStep(1)
    setError(null)
    onClose()
  }

  /*
   * Starting delivery does not enable the method; only a successful final
   * code check does.
   */

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !pending && close()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>일회용 코드 켜기</DialogTitle>
          <DialogDescription>
            {view.methods.find((method) => method.key === 'otp')?.description}
          </DialogDescription>
        </DialogHeader>
        <form id="mfa-otp" onSubmit={step === 1 ? start : confirm} noValidate>
          <FieldGroup>
            {step === 1 ? <PasswordField view={view} value={password} onChange={setPassword} /> : <>
              <p className="text-sm text-muted-foreground">등록된 휴대폰(또는 계정 이메일)으로 코드를 보냈습니다. 10분 안에 입력하세요.</p>
              <Field data-invalid={error ? true : undefined}>
                <FieldLabel htmlFor="mfa-otp-code">인증 코드</FieldLabel>
                <CodeInput id="mfa-otp-code" value={code} onChange={setCode} />
              </Field>
            </>}
            {error ? <FieldError>{error}</FieldError> : null}
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="submit" form="mfa-otp" disabled={pending || (step === 1 ? view.passwordRequired && !password : code.length !== 6)}>
            {pending ? <Spinner data-icon="inline-start" /> : null}
            {step === 1 ? '인증 코드 받기' : '확인'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function HotpDialog({ view, open, onClose }: { view: EnrollmentView; open: boolean; onClose: () => void }) {
  const refresh = useRefresh()
  const [label, setLabel] = useState('')
  const [token, setToken] = useState<{ secret: string; tokenId: string } | null>(null)
  const [code, setCode] = useState('')
  const [done, setDone] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function close() {
    setLabel('')
    setToken(null)
    setCode('')
    setDone(false)
    setError(null)
    onClose()
  }

  async function create(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      const result = await apiFetch<{ secretBase32: string; tokenId: string }>('/api/mfa/hotp/enroll', {
        method: 'POST',
        body: JSON.stringify({ label: label.trim() }),
      })
      setToken({ secret: result.secretBase32, tokenId: result.tokenId })
      await refresh()
    } catch (cause) {
      setError('토큰을 등록하지 못했습니다.')
      if (cause instanceof ApiError && cause.status === 403) await refresh()
    } finally {
      setPending(false)
    }
  }

  async function confirm(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      await apiFetch('/api/mfa/hotp/verify', { method: 'POST', body: JSON.stringify({ code, tokenId: token!.tokenId }) })
      setDone(true)
      await refresh()
    } catch {
      setError('코드가 올바르지 않습니다. 토큰의 새 코드를 입력하세요.')
      setCode('')
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !pending && close()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>보안 토큰 추가</DialogTitle>
          <DialogDescription>
            {done ? '토큰을 확인했습니다.' : token ? '토큰 키를 토큰에 등록한 뒤, 토큰이 보여주는 코드를 입력하세요.' : view.methods.find((m) => m.key === 'hotp')?.description}
          </DialogDescription>
        </DialogHeader>

        {done ? null : token ? (
          <form id="mfa-hotp-confirm" onSubmit={confirm} noValidate>
            <FieldGroup>
              <Field>
                <FieldLabel>{view.labels.hotpSecret}</FieldLabel>
                <div className="flex items-center gap-2">
                  <code className="min-w-0 flex-1 truncate rounded-md bg-muted px-2 py-1.5 font-mono text-xs">{token.secret}</code>
                  <CopyButton text={token.secret} label={view.labels.copy} />
                </div>
                <FieldDescription>이 키는 지금만 볼 수 있습니다.</FieldDescription>
              </Field>
              <Field data-invalid={error ? true : undefined}>
                <FieldLabel htmlFor="mfa-hotp-code">{view.labels.hotpVerify}</FieldLabel>
                <CodeInput id="mfa-hotp-code" value={code} onChange={setCode} />
                {error ? <FieldError>{error}</FieldError> : null}
              </Field>
            </FieldGroup>
          </form>
        ) : (
          <form id="mfa-hotp-create" onSubmit={create} noValidate>
            <FieldGroup>
              <Field data-invalid={error ? true : undefined}>
                <FieldLabel htmlFor="mfa-hotp-label">{view.labels.hotpName}</FieldLabel>
                <Input id="mfa-hotp-label" maxLength={64} value={label} onChange={(event) => setLabel(event.target.value)} />
                {error ? <FieldError>{error}</FieldError> : null}
              </Field>
            </FieldGroup>
          </form>
        )}

        <DialogFooter>
          {done ? (
            <Button onClick={close}>{view.labels.done}</Button>
          ) : token ? (
            <Button type="submit" form="mfa-hotp-confirm" disabled={pending || code.length !== 6}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {view.labels.verify}
            </Button>
          ) : (
            <Button type="submit" form="mfa-hotp-create" disabled={pending || !label.trim()}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {view.labels.add}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function BackupDialog({ view, open, onClose }: { view: EnrollmentView; open: boolean; onClose: () => void }) {
  const [password, setPassword] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function close() {
    setPassword('')
    setCodes(null)
    setError(null)
    onClose()
  }

  async function generate(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    const result = await authClient.twoFactor.generateBackupCodes({
      ...(view.passwordRequired ? { password } : {}),
    } as { password: string })
    setPending(false)
    if (result.error || !result.data?.backupCodes) {
      setError(message(result.error, '백업 코드를 만들지 못했습니다.'))
      return
    }
    setCodes(result.data.backupCodes)
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !pending && close()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{view.backupCodes.label}</DialogTitle>
          <DialogDescription>{view.backupCodes.description}</DialogDescription>
        </DialogHeader>
        {codes ? (
          <BackupCodes view={view} codes={codes} />
        ) : (
          <form id="mfa-backup" onSubmit={generate} noValidate>
            <FieldGroup>
              <PasswordField view={view} value={password} onChange={setPassword} />
              {error ? <FieldError>{error}</FieldError> : null}
            </FieldGroup>
          </form>
        )}
        <DialogFooter>
          {codes ? (
            <Button onClick={close}>{view.labels.done}</Button>
          ) : (
            <Button type="submit" form="mfa-backup" disabled={pending || (view.passwordRequired && !password)}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              새로 받기
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function DisableDialog({ view, open, onClose }: { view: EnrollmentView; open: boolean; onClose: () => void }) {
  const refresh = useRefresh()
  const [password, setPassword] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function disable(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setPending(true)
    const result = await authClient.twoFactor.disable({
      ...(view.passwordRequired ? { password } : {}),
    } as { password: string })
    setPending(false)
    if (result.error) {
      setError(message(result.error, '끄지 못했습니다.'))
      return
    }
    toast.success('2차 인증을 껐습니다.')
    setPassword('')
    await refresh()
    onClose()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !pending && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{view.disable.label}</DialogTitle>
          <DialogDescription>{view.disable.description}</DialogDescription>
        </DialogHeader>
        <form id="mfa-disable" onSubmit={disable} noValidate>
          <FieldGroup>
            <PasswordField view={view} value={password} onChange={setPassword} />
            {error ? <FieldError>{error}</FieldError> : null}
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
            취소
          </Button>
          <Button type="submit" form="mfa-disable" variant="destructive" disabled={pending || (view.passwordRequired && !password)}>
            {pending ? <Spinner data-icon="inline-start" /> : null}
            끄기
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
