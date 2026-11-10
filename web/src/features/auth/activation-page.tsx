import { useQuery } from '@tanstack/react-query'
import { CheckCircle2Icon, EyeIcon, EyeOffIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { LoadingScreen } from '@/components/loading-screen'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from '@/components/ui/input-group'
import { Spinner } from '@/components/ui/spinner'
import {
  activateAccount,
  checkPassword,
  inspectActivation,
  type ActivationUi,
} from '@/lib/activation'

// The token travels in the URL fragment so it never reaches server logs or Referer.
function readToken(): string {
  return window.location.hash.replace(/^#/, '')
}

export function ActivationPage() {
  const [token] = useState(readToken)
  const { data, isPending, error } = useQuery({
    queryKey: ['activation', token],
    queryFn: () => inspectActivation(token),
    enabled: token.length > 0,
    retry: false,
    staleTime: Infinity,
  })

  if (token.length > 0 && isPending) return <LoadingScreen />
  if (!data || error) {
    return (
      <Shell>
        <Alert variant="destructive">
          <AlertDescription>
            링크가 올바르지 않거나 만료되었습니다. 관리자에게 새 링크를 요청하세요.
          </AlertDescription>
        </Alert>
      </Shell>
    )
  }
  return <ActivationForm token={token} email={data.email} ui={data.ui} />
}

function ActivationForm({ token, email, ui }: { token: string; email: string; ui: ActivationUi }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [visible, setVisible] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    if (password !== confirm) return setError(ui.messages.mismatch)
    const problem = checkPassword(password, ui)
    if (problem) return setError(problem)
    setPending(true)
    const secret = password
    setPassword('')
    setConfirm('')
    const result = await activateAccount(token, secret)
    setPending(false)
    if (result === 'ok') {
      // Drop the link from the address bar and history.
      window.history.replaceState(null, '', '/activate')
      setDone(true)
      return
    }
    setError(
      result === 'invalid_link'
        ? ui.messages.invalid_link
        : result === 'rate_limited'
          ? ui.messages.rate_limited
          : ui.messages.unavailable,
    )
  }

  if (done) {
    return (
      <Shell>
        <div className="flex flex-col items-center gap-3 text-center">
          <CheckCircle2Icon className="size-8 text-muted-foreground" />
          <h1 className="text-xl font-semibold">{ui.done.title}</h1>
          <p className="text-sm text-muted-foreground">{ui.done.description}</p>
        </div>
        <Button size="lg" asChild>
          <a href="/auth/login">{ui.done.action}</a>
        </Button>
      </Shell>
    )
  }

  const fields = [
    { ...ui.fields[0]!, value: password, set: setPassword },
    { ...ui.fields[1]!, value: confirm, set: setConfirm },
  ]

  return (
    <Shell identifier={email}>
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">{ui.title}</h1>
        <p className="text-sm text-muted-foreground">{ui.description}</p>
      </div>
      <form onSubmit={submit} noValidate>
        <input type="hidden" name="username" autoComplete="username" value={email} readOnly />
        <FieldGroup>
          {error ? (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          {fields.map((field, index) => (
            <Field key={field.name} data-invalid={error ? true : undefined}>
              <FieldLabel htmlFor={`activation-${field.name}`}>{field.label}</FieldLabel>
              <InputGroup>
                <InputGroupInput
                  id={`activation-${field.name}`}
                  type={visible ? 'text' : 'password'}
                  autoComplete={field.autocomplete}
                  autoFocus={index === 0}
                  required
                  value={field.value}
                  disabled={pending}
                  onChange={(event) => field.set(event.target.value)}
                />
                {index === 0 ? (
                  <InputGroupAddon align="inline-end">
                    <InputGroupButton
                      size="icon-xs"
                      aria-label={visible ? '숨기기' : '보기'}
                      onClick={() => setVisible((current) => !current)}
                    >
                      {visible ? <EyeOffIcon /> : <EyeIcon />}
                    </InputGroupButton>
                  </InputGroupAddon>
                ) : null}
              </InputGroup>
              {index === 0 ? <FieldDescription>{ui.requirements.join(' · ')}</FieldDescription> : null}
            </Field>
          ))}
          <Field>
            <Button type="submit" size="lg" disabled={pending || !password || !confirm}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {ui.submit.label}
            </Button>
          </Field>
        </FieldGroup>
      </form>
    </Shell>
  )
}

function Shell({ identifier, children }: { identifier?: string; children: React.ReactNode }) {
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted p-4 sm:p-6">
      <div className="w-full max-w-md overflow-hidden rounded-2xl bg-background shadow-sm ring-1 ring-foreground/10">
        <div className="flex items-center justify-center py-7">
          <span className="text-lg font-semibold">WorkPass</span>
        </div>
        <div className="h-px bg-border" />
        <div className="flex flex-col gap-6 px-6 pt-6 pb-8 sm:px-10">
          {identifier ? (
            <div className="flex justify-center">
              <div className="max-w-full truncate rounded-full bg-muted px-4 py-2 text-sm">{identifier}</div>
            </div>
          ) : null}
          {children}
        </div>
      </div>
    </main>
  )
}
