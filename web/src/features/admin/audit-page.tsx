import { useMutation } from '@tanstack/react-query'
import { ShieldCheckIcon, ShieldAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { AuditView } from '@/features/audit/audit-view'
import { apiFetch } from '@/lib/api'

type Verification = { verified: boolean; entries: number; legacyEntries: number; firstProblem: unknown }

/** Re-computes the hash chain of every recorded event; any edit or deletion in the past would break it. */
function ChainCheck() {
  const check = useMutation({
    mutationFn: async () => (await apiFetch<{ verification: Verification }>('/api/admin/audit-events/verify')).verification,
  })
  const result = check.data
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" size="sm" disabled={check.isPending} onClick={() => check.mutate()}>
          {check.isPending ? <Spinner data-icon="inline-start" /> : <ShieldCheckIcon data-icon="inline-start" />}
          기록이 바뀌지 않았는지 확인
        </Button>
        <span className="text-xs text-muted-foreground">기록마다 이전 기록의 지문을 이어 붙여 두어서, 과거 기록을 고치거나 지우면 여기서 드러납니다.</span>
      </div>
      {check.isError ? (
        <Alert variant="destructive">
          <AlertDescription>확인하지 못했습니다. 잠시 뒤에 다시 시도하세요.</AlertDescription>
        </Alert>
      ) : result ? (
        result.verified ? (
          <Alert>
            <ShieldCheckIcon />
            <AlertTitle>기록이 그대로입니다</AlertTitle>
            <AlertDescription>
              {result.entries.toLocaleString('ko-KR')}건을 모두 확인했고 어긋난 곳이 없습니다.
              {result.legacyEntries > 0 ? ` 지문을 이어 붙이기 전에 쌓인 ${result.legacyEntries.toLocaleString('ko-KR')}건은 확인 대상이 아닙니다.` : ''}
            </AlertDescription>
          </Alert>
        ) : (
          <Alert variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>기록이 바뀐 흔적이 있습니다</AlertTitle>
            <AlertDescription>
              {result.entries.toLocaleString('ko-KR')}건 중 어긋난 곳이 있습니다. 데이터베이스에 직접 접근한 기록이 있는지 확인하고, 백업과 비교하세요.
              {result.firstProblem ? ` 처음 어긋난 곳: ${typeof result.firstProblem === 'string' ? result.firstProblem : JSON.stringify(result.firstProblem)}` : ''}
            </AlertDescription>
          </Alert>
        )
      ) : null}
    </div>
  )
}

/** Everything recorded about sign-ins, changes and approvals, newest first. */
export function AuditPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">감사 로그</h1>
        <p className="text-sm text-muted-foreground">누가 언제 무엇을 했는지의 기록입니다. 줄을 누르면 기록된 내용을 모두 볼 수 있습니다.</p>
      </div>
      <ChainCheck />
      <AuditView keyPrefix="admin-audit" />
    </div>
  )
}
