import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearch } from '@tanstack/react-router'
import { ShieldCheckIcon } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { AuthShell } from '@/components/auth-shell'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { fingerprintEventId, loginConfigQuery } from '@/lib/fingerprint'
import { stepUpQuery } from '@/lib/queries'
import { TwoFactorForm } from './two-factor-form'

const AUTHORIZE_PATH = '/api/auth/oauth2/authorize'

/** Only the authorization endpoint of this site: never an address that leaves it. */
function authorizeTarget(value: string | undefined): string | null {
  return value && value.startsWith(`${AUTHORIZE_PATH}?`) && value.length <= 8192 ? value : null
}

/**
 * Where an app's authorization request lands when this browser has not yet
 * been checked. It reads the device, asks for a second factor when the server
 * wants one, then resumes the same request with the device event attached.
 */
export function VerifyDevicePage() {
  const queryClient = useQueryClient()
  const { next, challenge } = useSearch({ from: '/verify-device' })
  const target = authorizeTarget(next)
  const { data: loginConfig } = useQuery(loginConfigQuery)
  const stepUp = useQuery({ ...stepUpQuery, enabled: Boolean(challenge) })
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const started = useRef(-1)

  const needsSecondFactor = Boolean(challenge) && stepUp.data?.required === true && stepUp.data.state === 'pending'
  const waitingForChallenge = Boolean(challenge) && stepUp.isPending

  useEffect(() => {
    if (!target || !loginConfig || waitingForChallenge || needsSecondFactor) return
    if (started.current === attempt) return
    started.current = attempt
    setFailed(false)
    void (async () => {
      const eventId = await fingerprintEventId(loginConfig.fingerprint, 'oauth.authorize')
      if (!eventId) {
        setFailed(true)
        return
      }
      // Appended as written, so the request the app signed keeps its exact encoding.
      window.location.replace(`${target}&fingerprint_event_id=${encodeURIComponent(eventId)}`)
    })()
  }, [target, loginConfig, waitingForChallenge, needsSecondFactor, attempt])

  if (!target) {
    return (
      <AuthShell heading="기기 확인">
        <Alert variant="destructive">
          <AlertDescription>잘못된 요청입니다. 로그인하려던 앱에서 다시 시도하세요.</AlertDescription>
        </Alert>
      </AuthShell>
    )
  }

  if (needsSecondFactor && stepUp.data?.required) {
    const ui = stepUp.data.ui
    return (
      <AuthShell heading="추가 인증" badge={<ShieldCheckIcon />}>
        <div className="flex flex-col gap-2 text-center">
          <h1 className="text-xl font-semibold">{ui.title}</h1>
          <p className="text-sm text-muted-foreground">{ui.description}</p>
        </div>
        <TwoFactorForm
          ui={ui}
          onVerified={async () => {
            await queryClient.invalidateQueries({ queryKey: ['step-up'] })
          }}
        />
      </AuthShell>
    )
  }

  return (
    <AuthShell heading="기기 확인" badge={<ShieldCheckIcon />}>
      {failed ? (
        <>
          <Alert variant="destructive">
            <AlertDescription>기기를 확인하지 못했습니다. 잠시 후 다시 시도하세요.</AlertDescription>
          </Alert>
          <Button onClick={() => setAttempt((count) => count + 1)}>다시 시도</Button>
        </>
      ) : (
        <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <Spinner />
          기기를 확인하는 중입니다…
        </div>
      )}
    </AuthShell>
  )
}
