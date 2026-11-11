import { useQuery } from '@tanstack/react-query'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  appActivityQuery,
  KIND_LABELS,
  METHOD_LABELS,
  REASON_LABELS,
  RISK_ACTIONS,
  SCOPE_LABELS,
  type Risk,
} from '@/lib/app-activity'
import { formatDateTime } from '@/lib/format'
import { PROTOCOL_LABELS } from '@/lib/integrations'

export type ActivityUser = { id: string; name: string; email: string }

function RiskCell({ risk, empty }: { risk: Risk | null; empty?: string }) {
  if (!risk) {
    return <span className="text-xs text-muted-foreground">{empty ?? '기록 없음'}</span>
  }
  const action = RISK_ACTIONS[risk.action] ?? { label: risk.action, tone: 'outline' as const }
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge variant={action.tone}>{action.label}</Badge>
        <span className="text-xs text-muted-foreground">{risk.scope === 'app' ? '이 앱 요청 당시' : '로그인 당시'}</span>
      </div>
      {risk.reasons.length > 0 ? (
        <span className="text-xs text-muted-foreground">{risk.reasons.map((reason) => REASON_LABELS[reason] ?? reason).join(' · ')}</span>
      ) : null}
    </div>
  )
}

function Scopes({ scopes }: { scopes: string[] }) {
  if (scopes.length === 0) return <span className="text-xs text-muted-foreground">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((scope) => (
        <Badge key={scope} variant="secondary">
          {SCOPE_LABELS[scope] ?? scope}
        </Badge>
      ))}
    </div>
  )
}

/** The apps a user is connected to, what they allowed and when, and the device verdict at each moment. */
export function UserAppsDialog({ user, onClose }: { user: ActivityUser | null; onClose: () => void }) {
  return (
    <Dialog open={user !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>{user?.name} 연결된 앱</DialogTitle>
          <DialogDescription>
            {user?.email}이(가) 로그인하거나 권한을 허용한 앱입니다. 위험도는 그 순간의 기기 판정을 복사해 둔 값이라, 기기 위험 판정이 꺼져 있던 때는 "기록 없음"입니다.
          </DialogDescription>
        </DialogHeader>
        {user ? <Body userId={user.id} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function Body({ userId }: { userId: string }) {
  const { data, isPending, error } = useQuery(appActivityQuery(userId))
  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>연결된 앱 정보를 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  if (isPending) return <Skeleton className="h-48 rounded-xl" />
  if (data.apps.length === 0 && data.events.length === 0) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyTitle>연결된 앱이 없습니다</EmptyTitle>
          <EmptyDescription>이 사용자가 로그인하거나 권한을 허용한 앱이 아직 없습니다.</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }
  return (
    <Tabs defaultValue="apps" className="gap-4">
      <TabsList variant="line">
        <TabsTrigger value="apps">앱 {data.apps.length}</TabsTrigger>
        <TabsTrigger value="events">이력 {data.events.length}</TabsTrigger>
      </TabsList>
      <TabsContent value="apps">
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>앱</TableHead>
                <TableHead>허용한 권한</TableHead>
                <TableHead>최근 로그인</TableHead>
                <TableHead>가장 최근 위험도</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.apps.map((app) => (
                <TableRow key={app.subject}>
                  <TableCell>
                    <div className="flex flex-col gap-0.5">
                      <span className="font-medium">{app.name}</span>
                      <span className="text-xs text-muted-foreground">
                        {PROTOCOL_LABELS[app.protocol] ?? app.protocol} · 로그인 {app.signIns}회
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    {app.consent ? (
                      <div className="flex flex-col gap-1">
                        <Scopes scopes={app.consent.scopes} />
                        <span className="text-xs text-muted-foreground">{formatDateTime(app.consent.grantedAt)} 허용</span>
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">따로 허용하는 단계가 없는 앱</span>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(app.lastAt)}</TableCell>
                  <TableCell>
                    <RiskCell risk={app.lastRisk} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </TabsContent>
      <TabsContent value="events">
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>시각</TableHead>
                <TableHead>앱</TableHead>
                <TableHead>구분</TableHead>
                <TableHead>권한</TableHead>
                <TableHead>당시 위험도</TableHead>
                <TableHead>국가</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.events.map((event) => (
                <TableRow key={event.id}>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(event.at)}</TableCell>
                  <TableCell className="font-medium">{event.app.name}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    {KIND_LABELS[event.kind]}
                    {event.method ? <span className="text-xs text-muted-foreground"> · {METHOD_LABELS[event.method] ?? event.method}</span> : null}
                  </TableCell>
                  <TableCell>
                    <Scopes scopes={event.scopes} />
                  </TableCell>
                  <TableCell>
                    <RiskCell risk={event.risk} />
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{event.country ?? '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </TabsContent>
    </Tabs>
  )
}
