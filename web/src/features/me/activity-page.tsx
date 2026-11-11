import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2Icon, FlagIcon, MonitorIcon, ShieldAlertIcon, SmartphoneIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'
import { eventLabel } from '@/lib/audit-labels'
import { formatDateTime } from '@/lib/format'
import { myActivityQuery, type MyActivity } from '@/lib/me'

type Login = MyActivity['logins'][number]

/** Recent sign-ins by device, security events of the last 30 days, and a way to report what is not theirs. */
export function ActivityPage() {
  const activity = useQuery(myActivityQuery)
  const [reporting, setReporting] = useState<Login | 'general' | null>(null)

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-8">
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-xl font-semibold">최근 활동</h1>
          <p className="text-sm text-muted-foreground">내 계정으로 로그인한 기기와 최근 30일 동안의 보안 활동입니다.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setReporting('general')}>
          <FlagIcon data-icon="inline-start" />
          의심스러운 활동 신고
        </Button>
      </div>

      {activity.isPending ? (
        <Skeleton className="h-64 w-full" />
      ) : activity.error ? (
        <Alert variant="destructive">
          <AlertDescription>활동을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : (
        <>
          <section className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold">로그인</h2>
            {activity.data.logins.length === 0 ? (
              <p className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">로그인 기록이 없습니다. 이 기능이 켜진 뒤의 로그인부터 기록됩니다.</p>
            ) : (
              <ul className="flex flex-col divide-y rounded-xl border">
                {activity.data.logins.map((login) => (
                  <li key={login.loginId} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                    {login.os === 'iOS' || login.os === 'Android' ? <SmartphoneIcon className="size-4 shrink-0 text-muted-foreground" /> : <MonitorIcon className="size-4 shrink-0 text-muted-foreground" />}
                    <div className="flex min-w-0 flex-1 basis-56 flex-col gap-0.5">
                      <span className="flex flex-wrap items-center gap-2 text-sm font-medium">
                        {login.device}
                        {login.current ? <Badge variant="secondary">이 기기</Badge> : null}
                      </span>
                      <span className="text-xs text-muted-foreground">{login.location ?? login.ip ?? '알 수 없음'}</span>
                      <span className="text-xs text-muted-foreground">
                        마지막 로그인 {formatDateTime(login.lastAt)} <span className="whitespace-nowrap">· {login.count}회</span>
                      </span>
                    </div>
                    {login.reported ? (
                      <Badge variant="outline">신고함</Badge>
                    ) : (
                      <Button variant="outline" size="sm" onClick={() => setReporting(login)}>
                        관리자에게 보고
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold">보안 활동 (최근 30일)</h2>
            {activity.data.events.length === 0 ? (
              <p className="rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground">최근 30일 동안 계정 보안과 관련된 변화가 없습니다.</p>
            ) : (
              <ul className="flex flex-col divide-y rounded-xl border">
                {activity.data.events.map((event) => {
                  const failed = event.outcome === 'failure'
                  const who = event.actor === 'administrator' ? `관리자${event.actorName ? ` ${event.actorName}` : ''}가 함` : event.actor === 'system' ? '시스템이 함' : event.byAdministrator ? '관리자가 함' : '내가 함'
                  const where = [event.place, event.ip].filter(Boolean).join(' · ')
                  const how = [event.device, event.detail].filter(Boolean).join(' · ')
                  return (
                    <li key={event.id} className="flex items-start gap-3 px-4 py-3">
                      {failed ? <ShieldAlertIcon className="mt-0.5 size-4 shrink-0 text-destructive" /> : <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-primary" />}
                      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                          <span className="text-sm font-medium">{eventLabel(event.type)}</span>
                          {failed ? <Badge variant="destructive">실패</Badge> : null}
                          {event.actor === 'administrator' || event.byAdministrator ? <Badge variant="outline">관리자 작업</Badge> : null}
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {who}
                          {how ? ` · ${how}` : ''}
                        </span>
                        {where ? <span className="text-xs text-muted-foreground">{where}</span> : null}
                      </div>
                      <span className="shrink-0 whitespace-nowrap text-xs text-muted-foreground">{formatDateTime(event.at)}</span>
                    </li>
                  )
                })}
              </ul>
            )}
          </section>
        </>
      )}

      <ReportDialog key={reporting === null ? 'closed' : typeof reporting === 'string' ? reporting : reporting.loginId} target={reporting} onClose={() => setReporting(null)} />
    </div>
  )
}

function ReportDialog({ target, onClose }: { target: Login | 'general' | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [summary, setSummary] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  const login = target !== null && target !== 'general' ? target : null

  const send = useMutation({
    mutationFn: () => apiFetch('/api/me/suspicious-reports', { method: 'POST', body: JSON.stringify({ loginId: login?.loginId, summary: summary.trim() }) }),
    onSuccess: async () => {
      toast.success('관리자에게 알렸습니다.')
      await queryClient.invalidateQueries({ queryKey: myActivityQuery.queryKey })
      onClose()
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '신고하지 못했습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    send.mutate()
  }

  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && !send.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>의심스러운 활동 신고</DialogTitle>
            <DialogDescription>
              {login ? `${login.device} · ${login.location ?? login.ip ?? '위치 알 수 없음'}에서의 로그인을 내가 한 것이 아니라고 관리자에게 알립니다.` : '내가 하지 않은 로그인이나 이상한 계정 활동을 관리자에게 알립니다.'}
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="report-summary">무슨 일이 있었나요? (선택)</FieldLabel>
              <Textarea id="report-summary" rows={3} maxLength={500} value={summary} onChange={(event) => setSummary(event.target.value)} />
            </Field>
          </FieldGroup>
          <p className="text-xs text-muted-foreground">신고해도 계정이 자동으로 잠기지는 않습니다. 바로 조치가 필요하면 비밀번호를 바꾸고 모든 세션을 종료하세요.</p>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={send.isPending} onClick={onClose}>
              취소
            </Button>
            <Button type="submit" variant="destructive" disabled={send.isPending}>
              {send.isPending ? <Spinner data-icon="inline-start" /> : null}
              신고
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
