import { startAuthentication } from '@simplewebauthn/browser'
import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp'
import { Spinner } from '@/components/ui/spinner'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ApiError, apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import type { StepUpUi } from '@/lib/step-up'

/** The person closed the browser's passkey prompt, or it timed out. The library wraps the browser's error. */
function isPasskeyDeclined(cause: unknown): boolean {
  if (!(cause instanceof Error)) return false
  const code = (cause as { code?: unknown }).code
  const original = (cause as { cause?: unknown }).cause
  return (
    cause.name === 'NotAllowedError' ||
    code === 'ERROR_CEREMONY_ABORTED' ||
    (original instanceof Error && original.name === 'NotAllowedError')
  )
}

/**
 * Second-factor form. Every label, hint and message comes from `ui`, the
 * definition the server sent; this component only runs the verification.
 */
export function TwoFactorForm({
  ui,
  onVerified,
  onCancel,
}: {
  ui: StepUpUi
  onVerified: () => Promise<void> | void
  onCancel?: () => void
}) {
  const [methodKey, setMethodKey] = useState(ui.methods[0]?.key ?? 'backup_code')
  const method = ui.methods.find((entry) => entry.key === methodKey) ?? ui.methods[0]!
  const [code, setCode] = useState('')
  const [pending, setPending] = useState(false)
  const [otpSent, setOtpSent] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function failure(status: number | undefined): string {
    if (status === 429) return ui.messages.rate_limited
    if (status === 503) return ui.messages.record_failed
    return ui.messages.invalid_code
  }

  async function sendOtp() {
    setError(null)
    setPending(true)
    const result = await authClient.twoFactor.sendOtp()
    setPending(false)
    if (result.error) {
      setError(failure(result.error.status))
      return
    }
    setOtpSent(true)
  }

  async function sendPush() {
    setError(null)
    setPending(true)
    try {
      const result = await apiFetch<{ result: string }>('/api/mfa/duo/verify', { method: 'POST', body: '{}' })
      if (result.result !== 'allow') {
        setError(ui.messages.push_denied)
        return
      }
      await onVerified()
    } catch (cause) {
      setError(failure(cause instanceof ApiError ? cause.status : undefined))
    } finally {
      setPending(false)
    }
  }

  /** The browser asks for the passkey; only the signed assertion goes to the server. */
  async function checkPasskey() {
    setError(null)
    setPending(true)
    try {
      const optionsJSON = await apiFetch<Parameters<typeof startAuthentication>[0]['optionsJSON']>('/api/security/step-up/passkey/options', { method: 'POST', body: '{}' })
      const assertion = await startAuthentication({ optionsJSON })
      await apiFetch('/api/security/step-up/passkey/verify', { method: 'POST', body: JSON.stringify(assertion) })
      await onVerified()
    } catch (cause) {
      if (cause instanceof ApiError) {
        setError(cause.status === 429 ? ui.messages.rate_limited : cause.status === 409 && /[가-힣]/.test(cause.message) ? cause.message : '패스키를 확인하지 못했습니다.')
      } else if (isPasskeyDeclined(cause)) {
        setError('패스키 확인이 취소되었거나 시간이 지났습니다. 다시 시도하세요.')
      } else {
        setError('패스키를 확인하지 못했습니다.')
      }
    } finally {
      setPending(false)
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setPending(true)
    if (method.key === 'hotp') {
      try {
        await apiFetch('/api/mfa/hotp/verify', { method: 'POST', body: JSON.stringify({ code }) })
      } catch (cause) {
        setPending(false)
        setError(failure(cause instanceof ApiError ? cause.status : undefined))
        setCode('')
        return
      }
      setPending(false)
      await onVerified()
      return
    }
    const result =
      method.key === 'totp'
        ? await authClient.twoFactor.verifyTotp({ code })
        : method.key === 'otp'
          ? await authClient.twoFactor.verifyOtp({ code })
          : await authClient.twoFactor.verifyBackupCode({ code: code.trim() })
    setPending(false)
    if (result.error) {
      setError(failure(result.error.status))
      setCode('')
      return
    }
    await onVerified()
  }

  const needsSend = Boolean(method.send) && !otpSent && method.input !== 'push'

  return (
    <form onSubmit={handleSubmit} noValidate>
      <FieldGroup>
        {ui.methods.length > 1 ? (
          <Tabs
            value={method.key}
            onValueChange={(value) => {
              setMethodKey(value as typeof methodKey)
              setOtpSent(false)
              setCode('')
              setError(null)
            }}
          >
            <TabsList className="w-full">
              {ui.methods.map((item) => (
                <TabsTrigger key={item.key} value={item.key}>
                  {item.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        ) : null}
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {method.input === 'passkey' ? (
          <Field>
            <FieldDescription>{method.send?.hint ?? method.description ?? ''}</FieldDescription>
            <Button type="button" onClick={checkPasskey} disabled={pending}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {method.send?.label ?? method.label}
            </Button>
          </Field>
        ) : method.input === 'push' && method.send ? (
          <Field>
            <FieldDescription>{method.send.hint}</FieldDescription>
            <Button type="button" onClick={sendPush} disabled={pending}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {method.send.label}
            </Button>
          </Field>
        ) : needsSend && method.send ? (
          <Field>
            <FieldDescription>{method.send.hint}</FieldDescription>
            <Button type="button" onClick={sendOtp} disabled={pending}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {method.send.label}
            </Button>
          </Field>
        ) : (
          <>
            <Field>
              <FieldLabel htmlFor="two-factor-code">{method.fieldLabel}</FieldLabel>
              {method.input === 'otp6' ? (
                <InputOTP
                  id="two-factor-code"
                  maxLength={6}
                  value={code}
                  onChange={setCode}
                  autoFocus
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  pattern="^[0-9]*$"
                >
                  <InputOTPGroup>
                    {Array.from({ length: 6 }, (_, index) => (
                      <InputOTPSlot key={index} index={index} />
                    ))}
                  </InputOTPGroup>
                </InputOTP>
              ) : (
                <Input
                  id="two-factor-code"
                  autoFocus
                  autoComplete="off"
                  autoCapitalize="off"
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                />
              )}
            </Field>
            <Field>
              <Button
                type="submit"
                disabled={pending || (method.input === 'otp6' ? code.length !== 6 : !code.trim())}
              >
                {pending ? <Spinner data-icon="inline-start" /> : null}
                {ui.submit.label}
              </Button>
            </Field>
          </>
        )}
        {onCancel ? (
          <Field>
            <Button type="button" variant="outline" onClick={onCancel} disabled={pending}>
              {ui.alternatives[0]?.label}
            </Button>
          </Field>
        ) : null}
      </FieldGroup>
    </form>
  )
}
