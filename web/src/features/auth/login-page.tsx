import { shareLocation } from '@/lib/location'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearch } from '@tanstack/react-router'
import {
  ArrowRightIcon,
  EyeIcon,
  EyeOffIcon,
  KeyRoundIcon,
  RectangleEllipsisIcon,
  ShieldCheckIcon,
} from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { AuthShell } from '@/components/auth-shell'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Field, FieldError, FieldGroup, FieldLabel, FieldSeparator } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from '@/components/ui/input-group'
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from '@/components/ui/item'
import { Spinner } from '@/components/ui/spinner'
import { EnrollmentDialogs } from '@/features/security/mfa-section'
import { enrollmentQuery, type EnrollmentView } from '@/lib/mfa'
import { ApiError, apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { fingerprintEventId, loginConfigQuery, startFingerprint } from '@/lib/fingerprint'
import {
  idxChallenge,
  idxIdentify,
  idxIntrospect,
  idxRequestLink,
  type IdxIcon,
  type IdxState,
  type IdxUiAlternative,
  type IdxUiField,
} from '@/lib/idx'
import { normalizeIdentifier, opaqueSignIn, type OpaqueSignInResult } from '@/lib/opaque'
import { sessionQuery } from '@/lib/queries'
import type { StepUpUi } from '@/lib/step-up'
import { TwoFactorForm } from './two-factor-form'

const ICONS: Record<IdxIcon, ReactNode> = {
  password: <RectangleEllipsisIcon />,
  passkey: <KeyRoundIcon />,
}

export function LoginPage() {
  const queryClient = useQueryClient()
  const { oq } = useSearch({ from: '/login' })
  const { data: loginConfig } = useQuery(loginConfigQuery)
  const fingerprintConfig = loginConfig?.fingerprint ?? null
  const { data: existingSession } = useQuery(sessionQuery)

  // The whole screen is `idx.ui`, defined by the server.
  const [idx, setIdx] = useState<IdxState | null>(null)
  const [stepUp, setStepUp] = useState<StepUpUi | null>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const [identifier, setIdentifier] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [fatal, setFatal] = useState(false)
  const [finishing, setFinishing] = useState(false)
  const [folded, setFolded] = useState(false)
  const [warm, setWarm] = useState(false)
  const continued = useRef(false)
  const [enrolling, setEnrolling] = useState(false)
  const [enrollKind, setEnrollKind] = useState<'totp' | 'otp' | 'hotp' | null>(null)
  const enrollment = useQuery({ ...enrollmentQuery, enabled: enrolling })

  // The first card waits a moment so the folded line is seen before it opens.
  useEffect(() => {
    const timer = setTimeout(() => setWarm(true), 700)
    return () => clearTimeout(timer)
  }, [])

  /** Fold the card shut, swap what it shows, and open it again. */
  async function fold(update: () => void) {
    setFolded(true)
    await new Promise((resolve) => setTimeout(resolve, 950))
    setNotice(null)
    update()
    setFolded(false)
  }

  async function start() {
    const state = await idxIntrospect(oq)
    await fold(() => {
      setValues({})
      setError(null)
      setIdx(state)
    })
  }

  useEffect(() => {
    let active = true
    idxIntrospect(oq)
      .then((state) => active && setIdx(state))
      .catch(() => active && setFatal(true))
    return () => {
      active = false
    }
  }, [oq])

  useEffect(() => {
    startFingerprint(fingerprintConfig)
  }, [fingerprintConfig])

  const messages = idx?.ui.messages

  /** Sign-in is complete: resume the signed authorization request (WorkPass code flow). */
  async function finish() {
    // Sign-in success and the session query can both land here; the signed
    // request is single use, so only the first call may continue it.
    if (continued.current) return
    continued.current = true
    setFinishing(true)
    await queryClient.invalidateQueries({ queryKey: ['session'] })
    try {
      const result = await apiFetch<{ redirect?: boolean; url?: string }>(
        '/api/auth/oauth2/continue',
        { method: 'POST', body: JSON.stringify({ postLogin: true, oauth_query: oq }) },
      )
      if (!result.url) throw new Error('missing redirect')
      window.location.assign(result.url)
    } catch (failure) {
      continued.current = false
      setFinishing(false)
      setStepUp(null)
      await start().catch(() => setFatal(true))
      setError(
        failure instanceof ApiError && failure.status === 403
          ? (messages?.forbidden_app ?? null)
          : (messages?.incomplete ?? null),
      )
    }
  }

  /** A signed-in user whose required second factor is not set up yet gets the setup card first. */
  async function afterSignIn() {
    const view = await queryClient.fetchQuery({ ...enrollmentQuery, staleTime: 0 }).catch(() => null)
    if (view?.mustEnroll) {
      await fold(() => setEnrolling(true))
      return
    }
    await finish()
  }

  // Setting a method up completes the requirement: carry on with the sign-in.
  useEffect(() => {
    if (enrolling && enrollment.data && !enrollment.data.mustEnroll) {
      setEnrolling(false)
      void finish()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enrolling, enrollment.data])

  // A browser that already holds a session only needs to resume the request.
  useEffect(() => {
    if (existingSession) void finish()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [existingSession])

  async function signInWithPasskey() {
    if (!idx) return
    setError(null)
    setPending(true)
    const eventId = await fingerprintEventId(fingerprintConfig, 'login.passkey')
    const result = await authClient.signIn.passkey(
      undefined,
      eventId
        ? {
            onRequest: (context) => {
              try {
                const body = typeof context.body === 'string' ? JSON.parse(context.body) : {}
                return { ...context, body: JSON.stringify({ ...body, fingerprint: { event_id: eventId } }) }
              } catch {
                return context
              }
            },
          }
        : undefined,
    )
    setPending(false)
    if (result?.error) {
      const refusal = result.error as { code?: unknown; message?: unknown }
      const byPlace = refusal.code === 'location_denied' || String(refusal.message ?? '').includes('location')
      setError(
        result.error.status === 429
          ? idx.ui.messages.rate_limited
          : byPlace
            ? idx.ui.messages.location_denied
            : idx.ui.messages.passkey_failed,
      )
      return
    }
    await afterSignIn()
  }

  async function run<T>(task: () => Promise<T>): Promise<T | undefined> {
    setError(null)
    setPending(true)
    try {
      return await task()
    } catch (failure) {
      setError(
        failure instanceof ApiError && failure.status === 429
          ? (messages?.rate_limited ?? null)
          : (messages?.unavailable ?? null),
      )
      return undefined
    } finally {
      setPending(false)
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!idx) return
    const { action } = idx.ui

    if (action === 'identify') {
      const email = normalizeIdentifier(values.identifier ?? '')
      if (!email) return
      setIdentifier(email)
      const next = await run(async () =>
        idxIdentify(idx.stateHandle, email, oq),
      )
      if (next) {
        await fold(() => {
          setValues({})
          setIdx(next)
        })
      }
      return
    }

    if (action === 'passkey') {
      await signInWithPasskey()
      return
    }

    if (action === 'share-location') {
      setError(null)
      setPending(true)
      const outcome = await shareLocation()
      setPending(false)
      if (outcome === 'ok') {
        await start().catch(() => setFatal(true))
        return
      }
      const key = { outside: 'location_outside', inaccurate: 'location_inaccurate', blocked: 'location_blocked', rate_limited: 'rate_limited', unavailable: 'unavailable' } as const
      setError(idx.ui.messages[key[outcome]])
      return
    }

    if (action === 'opaque-password') {
      const secret = values.passcode ?? ''
      if (!secret) return
      setValues({})
      setError(null)
      setPending(true)
      const eventId = await fingerprintEventId(fingerprintConfig, 'login.password', identifier)
      const result: OpaqueSignInResult = await opaqueSignIn(identifier, secret, eventId)
      setPending(false)
      if (result.status !== 'ok') {
        setError(idx.ui.messages[result.status])
        return
      }
      if (result.stepUp) {
        const challenge = result.stepUp.ui
        await fold(() => setStepUp(challenge))
        return
      }
      await afterSignIn()
    }
  }

  async function chooseOption(id: string) {
    if (!idx) return
    const next = await run(() => idxChallenge(idx.stateHandle, id))
    if (next) await fold(() => setIdx(next))
  }

  async function runAlternative(alternative: IdxUiAlternative) {
    if (!idx) return
    if (alternative.action === 'passkey') {
      await signInWithPasskey()
    } else if (alternative.action === 'request-link') {
      setError(null)
      setNotice(null)
      setPending(true)
      try {
        await idxRequestLink(idx.stateHandle)
        setNotice(idx.ui.messages.link_sent)
      } catch (failure) {
        setError(failure instanceof ApiError && failure.status === 429 ? idx.ui.messages.rate_limited : idx.ui.messages.link_unavailable)
      } finally {
        setPending(false)
      }
    } else if (alternative.action === 'skip-location') {
      // An exempt account can sign in from anywhere; the server decides at the end.
      const next = await run(() => idxIntrospect(oq, { skipLocation: true }))
      if (next) await fold(() => setIdx(next))
    } else if (alternative.action === 'switch-method') {
      const next = await run(() => idxChallenge(idx.stateHandle))
      if (next) await fold(() => setIdx(next))
    } else {
      setIdentifier('')
      setStepUp(null)
      await start().catch(() => setFatal(true))
    }
  }

  if (fatal) {
    return (
      <AuthShell>
        <Alert variant="destructive">
          <AlertDescription>지금은 로그인할 수 없습니다. 잠시 후 다시 시도하세요.</AlertDescription>
        </Alert>
      </AuthShell>
    )
  }
  if (!idx) return <AuthShell folded />

  if (enrolling) {
    const view: EnrollmentView | undefined = enrollment.data
    const options = (view?.methods ?? []).filter(
      (method) => method.state === 'available' && (method.key === 'totp' || method.key === 'otp' || method.key === 'hotp'),
    )
    return (
      <AuthShell folded={folded || !view || finishing} identifier={identifier} badge={<ShieldCheckIcon />}>
        {view ? (
          <div className="flex flex-col gap-6">
            <div className="flex flex-col gap-1">
              <h1 className="text-xl font-semibold">{view.signIn.title}</h1>
              <p className="text-sm text-muted-foreground">{view.signIn.description}</p>
            </div>
            <div className="flex flex-col gap-3">
              <h2 className="text-sm font-medium text-muted-foreground">{view.signIn.requiredHeading}</h2>
              <p className="text-sm text-muted-foreground">{view.signIn.hint}</p>
              <ItemGroup className="gap-2">
                {options.map((method) => (
                  <Item key={method.key} variant="outline">
                    <ItemContent>
                      <ItemTitle>{method.label}</ItemTitle>
                      <ItemDescription>{method.description}</ItemDescription>
                    </ItemContent>
                    <ItemActions>
                      <Button variant="outline" size="sm" onClick={() => setEnrollKind(method.key as 'totp' | 'otp' | 'hotp')}>
                        {view.signIn.setup}
                      </Button>
                    </ItemActions>
                  </Item>
                ))}
              </ItemGroup>
              {options.length === 0 ? (
                <Alert>
                  <AlertDescription>지금 설정할 수 있는 방법이 없습니다. 관리자에게 문의하세요.</AlertDescription>
                </Alert>
              ) : null}
            </div>
            <Button
              variant="link"
              className="self-start px-0 text-muted-foreground"
              onClick={async () => {
                await authClient.signOut()
                setEnrolling(false)
                setIdentifier('')
                await start().catch(() => setFatal(true))
              }}
            >
              {view.signIn.back}
            </Button>
            <EnrollmentDialogs view={view} kind={enrollKind} onClose={() => setEnrollKind(null)} />
          </div>
        ) : null}
      </AuthShell>
    )
  }

  if (stepUp) {
    return (
      <AuthShell folded={folded || !warm || finishing} identifier={identifier} badge={<ShieldCheckIcon />}>
        <div className="flex flex-col gap-6">
          <div className="flex flex-col gap-1">
            <h1 className="text-xl font-semibold">{stepUp.title}</h1>
            <p className="text-sm text-muted-foreground">{stepUp.description}</p>
          </div>
          <TwoFactorForm ui={stepUp} onVerified={finish} />
          {stepUp.alternatives.map((alternative) => (
            <Button
              key={alternative.action}
              variant="link"
              className="self-start px-0 text-muted-foreground"
              onClick={async () => {
                await authClient.signOut()
                await runAlternative({ label: '', action: 'cancel', placement: 'after', variant: 'link' })
              }}
            >
              {alternative.label}
            </Button>
          ))}
        </div>
      </AuthShell>
    )
  }

  const { ui } = idx
  const before = ui.alternatives.filter((alternative) => alternative.placement === 'before')
  const after = ui.alternatives.filter((alternative) => alternative.placement === 'after')

  return (
    <AuthShell
      folded={folded || !warm || finishing}
      identifier={idx.identifier ?? undefined}
      badge={ui.badge ? ICONS[ui.badge] : undefined}
    >
      <div className="flex flex-col gap-6">
        <div className="flex flex-col gap-1">
          <h1 className="text-xl font-semibold">{ui.title}</h1>
          {ui.description ? <p className="text-sm text-muted-foreground">{ui.description}</p> : null}
        </div>

        {before.map((alternative) => (
          <AlternativeButton
            key={alternative.action}
            alternative={alternative}
            disabled={pending}
            pending={pending}
            onRun={runAlternative}
          />
        ))}
        {error && !ui.submit ? <FieldError>{error}</FieldError> : null}
        {notice && !error && !ui.submit ? <p className="text-sm text-muted-foreground" role="status">{notice}</p> : null}
        {ui.separator ? <FieldSeparator>{ui.separator}</FieldSeparator> : null}

        {ui.options.length > 0 ? (
          <ItemGroup className="gap-2">
            {ui.options.map((option) => (
              <MethodItem
                key={option.id}
                icon={ICONS[option.icon]}
                title={option.label}
                description={option.description}
                disabled={pending}
                onSelect={() => void chooseOption(option.id)}
              />
            ))}
          </ItemGroup>
        ) : null}

        {ui.submit ? (
          <form onSubmit={submit} noValidate>
            {ui.action === 'opaque-password' ? (
              /* Lets password managers pair the saved credential with this email. */
              <input type="hidden" name="username" autoComplete="username" value={identifier} readOnly />
            ) : null}
            <FieldGroup>
              {ui.fields.map((field) => (
                <ServerField
                  key={field.name}
                  field={field}
                  value={values[field.name] ?? ''}
                  invalid={Boolean(error)}
                  disabled={pending}
                  onChange={(value) => setValues((current) => ({ ...current, [field.name]: value }))}
                />
              ))}
              {error ? <FieldError>{error}</FieldError> : null}
              {notice && !error ? <p className="text-sm text-muted-foreground" role="status">{notice}</p> : null}
              <Field>
                <Button
                  type="submit"
                  size="lg"
                  disabled={
                    pending || ui.fields.some((field) => field.required && !(values[field.name] ?? '').trim())
                  }
                >
                  {pending ? <Spinner data-icon="inline-start" /> : null}
                  {ui.submit.label}
                </Button>
              </Field>
            </FieldGroup>
          </form>
        ) : null}

        {after.map((alternative) => (
          <AlternativeButton
            key={alternative.action}
            alternative={alternative}
            disabled={pending}
            pending={false}
            onRun={runAlternative}
          />
        ))}
      </div>
    </AuthShell>
  )
}

function AlternativeButton({
  alternative,
  disabled,
  pending,
  onRun,
}: {
  alternative: IdxUiAlternative
  disabled: boolean
  pending: boolean
  onRun: (alternative: IdxUiAlternative) => void
}) {
  const link = alternative.variant === 'link'
  return (
    <Button
      variant={alternative.variant}
      size={link ? 'default' : 'lg'}
      className={link ? 'self-start px-0 text-muted-foreground' : 'w-full'}
      disabled={disabled}
      onClick={() => onRun(alternative)}
    >
      {alternative.icon ? (
        pending ? <Spinner data-icon="inline-start" /> : <span data-icon="inline-start">{ICONS[alternative.icon]}</span>
      ) : null}
      {alternative.label}
    </Button>
  )
}

function ServerField({
  field,
  value,
  invalid,
  disabled,
  onChange,
}: {
  field: IdxUiField
  value: string
  invalid: boolean
  disabled: boolean
  onChange: (value: string) => void
}) {
  const [visible, setVisible] = useState(false)
  const id = `field-${field.name}`

  if (field.kind === 'password') {
    return (
      <Field data-invalid={invalid ? true : undefined}>
        <FieldLabel htmlFor={id}>{field.label}</FieldLabel>
        <InputGroup>
          <InputGroupInput
            id={id}
            type={visible ? 'text' : 'password'}
            autoComplete={field.autocomplete}
            autoFocus
            required={field.required}
            aria-invalid={invalid ? true : undefined}
            value={value}
            disabled={disabled}
            onChange={(event) => onChange(event.target.value)}
          />
          <InputGroupAddon align="inline-end">
            <InputGroupButton
              size="icon-xs"
              aria-label={visible ? '숨기기' : '보기'}
              onClick={() => setVisible((current) => !current)}
            >
              {visible ? <EyeOffIcon /> : <EyeIcon />}
            </InputGroupButton>
          </InputGroupAddon>
        </InputGroup>
      </Field>
    )
  }

  return (
    <Field data-invalid={invalid ? true : undefined}>
      <FieldLabel htmlFor={id}>{field.label}</FieldLabel>
      <Input
        id={id}
        type="email"
        aria-invalid={invalid ? true : undefined}
        inputMode="email"
        autoComplete={field.autocomplete}
        autoCapitalize="off"
        spellCheck={false}
        autoFocus
        required={field.required}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      />
    </Field>
  )
}

function MethodItem({
  icon,
  title,
  description,
  disabled,
  onSelect,
}: {
  icon: ReactNode
  title: string
  description?: string
  disabled?: boolean
  onSelect: () => void
}) {
  return (
    <Item variant="outline" asChild>
      <button type="button" className="text-left" disabled={disabled} onClick={onSelect}>
        <ItemMedia variant="icon">{icon}</ItemMedia>
        <ItemContent>
          <ItemTitle>{title}</ItemTitle>
          {description ? <ItemDescription>{description}</ItemDescription> : null}
        </ItemContent>
        <ItemActions>
          <ArrowRightIcon className="text-muted-foreground" />
        </ItemActions>
      </button>
    </Item>
  )
}
