import { AuditView } from '@/features/audit/audit-view'

/** Everything recorded about sign-ins, changes and approvals, newest first. */
export function AuditPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">감사 로그</h1>
        <p className="text-sm text-muted-foreground">누가 언제 무엇을 했는지의 기록입니다. 줄을 누르면 기록된 내용을 모두 볼 수 있습니다.</p>
      </div>
      <AuditView keyPrefix="admin-audit" />
    </div>
  )
}
