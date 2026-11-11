import { useSearch } from '@tanstack/react-router'
import { MapPinIcon } from 'lucide-react'
import { useState } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { shareLocation, type ShareOutcome } from '@/lib/location'
import { ApprovalCard } from '@/features/approvals/approval-card'

const FAILURES: Record<Exclude<ShareOutcome, 'ok'>, string> = {
  outside: '지금 위치는 허용된 장소 근처가 아닙니다. 지정된 장소 가까이에서 다시 시도하세요.',
  inaccurate: '위치가 충분히 정확하지 않습니다. 위치 서비스를 켜고 다시 시도하세요.',
  blocked: '브라우저가 위치 공유를 허용하지 않았습니다. 주소창의 위치 권한을 허용한 뒤 다시 시도하세요.',
  rate_limited: '시도가 너무 많습니다. 잠시 후 다시 시도하세요.',
  unavailable: '위치를 확인하지 못했습니다. 잠시 후 다시 시도하세요.',
}

/**
 * Where an app sign-in lands when the organization limits sign-in to certain
 * places and this browser has not shown it is in one. After the position is
 * accepted the person goes straight back to the sign-in they started.
 */
export function LocationPage() {
  const { redirect } = useSearch({ strict: false }) as { redirect?: string }
  const [pending, setPending] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)

  async function share() {
    setFailure(null)
    setPending(true)
    const outcome = await shareLocation()
    if (outcome === 'ok') {
      // Only a sign-in request of this server may be resumed.
      window.location.assign(redirect && redirect.startsWith('/api/auth/oauth2/authorize?') ? redirect : '/')
      return
    }
    setPending(false)
    setFailure(FAILURES[outcome])
  }

  return (
    <ApprovalCard>
      <div className="flex flex-col items-center gap-3 text-center">
        <MapPinIcon className="size-10 text-muted-foreground" />
        <h1 className="text-lg font-semibold">위치를 확인하세요</h1>
        <p className="text-sm text-muted-foreground">이 조직은 지정된 장소 근처에서만 로그인할 수 있습니다. 브라우저에서 내 위치를 공유해 주세요. 위치는 저장하지 않고, 허용된 장소 안인지만 확인합니다.</p>
      </div>
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <Button disabled={pending} onClick={share}>
        {pending ? <Spinner data-icon="inline-start" /> : null}
        내 위치 공유
      </Button>
    </ApprovalCard>
  )
}
