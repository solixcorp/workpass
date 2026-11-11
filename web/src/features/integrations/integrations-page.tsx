import { useQuery } from '@tanstack/react-query'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { ClaimsTab } from './claims-tab'
import { ProvisioningTab } from './provisioning-tab'
import { SignalsTab } from './signals-tab'
import type { Status } from './types'

function State({ on, configured }: { on: boolean; configured: boolean }) {
  if (!on) return <Badge variant="outline">꺼짐</Badge>
  return configured ? <Badge>사용 중</Badge> : <Badge variant="destructive">설정이 부족함</Badge>
}

function Card({ title, description, on, configured, children }: { title: string; description: string; on: boolean; configured: boolean; children?: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3 rounded-2xl border bg-card p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <h3 className="text-sm font-semibold">{title}</h3>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <State on={on} configured={configured} />
      </div>
      {children ? <div className="flex flex-col gap-1 text-xs text-muted-foreground">{children}</div> : null}
    </section>
  )
}

const OPERATION_STATES: Array<[keyof Status['scimOutbound']['operationCounts'], string]> = [
  ['succeeded', '성공'],
  ['failed', '실패'],
  ['pending', '대기'],
  ['in_progress', '진행 중'],
  ['outcome_unknown', '결과 불명'],
]

function Overview() {
  const query = useQuery({ queryKey: ['admin', 'integrations', 'status'], queryFn: () => apiFetch<Status>('/api/admin/integrations/status') })
  if (query.isPending) return <Skeleton className="h-64 w-full" />
  if (query.error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>연동 현황을 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  const s = query.data
  const last = (value: string | null) => (value ? `마지막 활동 ${formatDateTime(value)}` : '활동 기록 없음')
  return (
    <div className="flex flex-col gap-4">
      <Alert>
        <AlertDescription>
          이 기능들은 서버 환경변수로 켜고 설정합니다. 이 화면은 지금 상태를 보여 주고, 아래 탭에서 기록과 앱별 정책을 다룹니다. “설정이 부족함”은 값이 빠졌다는 뜻이며 실제 연결이 되는지는 확인하지 않습니다.
        </AlertDescription>
      </Alert>
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="사용자 프로비저닝 (SCIM 보내기)" description="이 시스템의 사용자 변경을 외부 시스템에 보냅니다. 배포 전체에 대상이 하나입니다." on={s.scimOutbound.enabled} configured={s.scimOutbound.configured}>
          {s.scimOutbound.baseUrlHost ? <span>대상: {s.scimOutbound.baseUrlHost}</span> : null}
          <span className="flex flex-wrap gap-x-3">
            {OPERATION_STATES.map(([key, label]) => (
              <span key={key}>
                {label} {s.scimOutbound.operationCounts[key]}
              </span>
            ))}
          </span>
          <span>{last(s.scimOutbound.lastActivityAt)}</span>
        </Card>
        <Card title="사용자 프로비저닝 (SCIM 받기)" description="외부 시스템이 이 시스템의 사용자를 만들고 고치게 합니다." on={s.scimInbound.enabled} configured={s.scimInbound.configured}>
          <span>{last(s.scimInbound.lastActivityAt)}</span>
        </Card>
        <Card title="보안 이벤트 보내기 (SSF)" description="계정 위험이 바뀌면 연결된 수신자에게 알립니다." on={s.ssfSender.enabled} configured={s.ssfSender.configured}>
          <span>스트림 {s.ssfSender.streamCount}개</span>
          <span>{last(s.ssfSender.lastActivityAt)}</span>
        </Card>
        <Card title="보안 이벤트 받기 (SSF)" description="외부에서 보내는 보안 이벤트를 받습니다." on={s.ssfReceiver.enabled} configured={s.ssfReceiver.configured}>
          <span>스트림 {s.ssfReceiver.streamCount}개</span>
          <span>{last(s.ssfReceiver.lastActivityAt)}</span>
        </Card>
      </div>
      <section className="flex flex-col gap-3 rounded-2xl border bg-card p-5">
        <h3 className="text-sm font-semibold">토큰에 담는 정보</h3>
        <p className="text-xs text-muted-foreground">앱에 내보내는 토큰과 응답에 어떤 정보를 실을 수 있는지 정하는 서버 스위치입니다. 앱마다의 허용 범위는 ‘클레임 발급’ 탭에서 정합니다.</p>
        <div className="flex flex-wrap gap-2">
          <Badge variant={s.claims.accountClaimsEnabled ? 'default' : 'outline'}>계정 정보 {s.claims.accountClaimsEnabled ? '켜짐' : '꺼짐'}</Badge>
          <Badge variant={s.claims.attributeClaimsEnabled ? 'default' : 'outline'}>사용자 속성 {s.claims.attributeClaimsEnabled ? '켜짐' : '꺼짐'}</Badge>
          <Badge variant={s.claims.scimAttributeReleaseEnabled ? 'default' : 'outline'}>SCIM으로 속성 전달 {s.claims.scimAttributeReleaseEnabled ? '켜짐' : '꺼짐'}</Badge>
        </div>
        <span className="text-xs text-muted-foreground">{s.claims.lastPolicyUpdateAt ? `정책 마지막 수정 ${formatDateTime(s.claims.lastPolicyUpdateAt)}` : '저장된 앱별 정책이 없습니다.'}</span>
      </section>
    </div>
  )
}

/** The features that connect this system to others: what is on, what has happened, and what each app may be told. */
export function IntegrationsPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold">연동</h1>
        <p className="text-sm text-muted-foreground">외부 시스템과의 사용자 동기화, 보안 이벤트 교환, 앱에 내보내는 정보를 확인합니다.</p>
      </div>
      <Tabs defaultValue="overview" className="gap-6">
        <TabsList variant="line" className="w-full justify-start overflow-x-auto">
          <TabsTrigger value="overview">현황</TabsTrigger>
          <TabsTrigger value="provisioning">프로비저닝 기록</TabsTrigger>
          <TabsTrigger value="signals">보안 이벤트</TabsTrigger>
          <TabsTrigger value="claims">클레임 발급</TabsTrigger>
        </TabsList>
        <TabsContent value="overview"><Overview /></TabsContent>
        <TabsContent value="provisioning"><ProvisioningTab /></TabsContent>
        <TabsContent value="signals"><SignalsTab /></TabsContent>
        <TabsContent value="claims"><ClaimsTab /></TabsContent>
      </Tabs>
    </div>
  )
}
