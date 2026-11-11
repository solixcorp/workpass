import { ShieldCheckIcon, UserIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { AuditView } from '@/features/audit/audit-view'
import { Panel } from './shared'

export function RolesTab({ roles }: { roles: string[] }) {
  const isAdmin = roles.includes('admin')
  return (
    <Panel
      title="관리자 역할"
      description="이 시스템의 역할은 관리자와 일반 사용자 두 가지입니다. 맞춤 역할이나 범위가 제한된 관리자는 아직 없습니다. 바꾸려면 위쪽 ⋯ 메뉴를 쓰세요."
    >
      <div className="flex flex-col gap-3">
        <div className="flex items-start gap-3 rounded-xl border bg-card p-4">
          <ShieldCheckIcon className={`mt-0.5 size-4 shrink-0 ${isAdmin ? 'text-primary' : 'text-muted-foreground'}`} />
          <div className="flex flex-col gap-0.5">
            <span className="flex items-center gap-2 text-sm font-medium">
              관리자 {isAdmin ? <Badge>부여됨</Badge> : <Badge variant="outline">없음</Badge>}
            </span>
            <span className="text-xs text-muted-foreground">사용자, 그룹, 앱, 정책, 설정, 감사 로그를 포함한 관리 콘솔 전체를 다룰 수 있습니다.</span>
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-xl border bg-card p-4">
          <UserIcon className="mt-0.5 size-4 shrink-0 text-primary" />
          <div className="flex flex-col gap-0.5">
            <span className="flex items-center gap-2 text-sm font-medium">
              사용자 <Badge variant="secondary">기본</Badge>
            </span>
            <span className="text-xs text-muted-foreground">할당된 앱을 열고 자신의 보안 설정을 관리합니다.</span>
          </div>
        </div>
      </div>
    </Panel>
  )
}

export function LogsTab({ id }: { id: string }) {
  return (
    <Panel title="시스템 로그" description="이 사용자가 한 일과 이 사용자에게 일어난 일입니다. 줄을 누르면 자세한 내용이 열립니다.">
      <AuditView userId={id} keyPrefix="admin-user-logs" />
    </Panel>
  )
}
