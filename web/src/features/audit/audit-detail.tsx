import { Link } from '@tanstack/react-router'
import { CopyIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { eventLabel } from '@/lib/audit-labels'
import { formatDateTime } from '@/lib/format'
import type { AuditEvent, Person } from './types'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b py-3 last:border-b-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all text-sm">{children}</dd>
    </div>
  )
}

function PersonRow({ id, person }: { id: string | null; person: Person }) {
  if (!id) return <span className="text-muted-foreground">없음</span>
  if (!person) return <span className="font-mono text-xs">{id}</span>
  return (
    <Link to="/admin/users/$id" params={{ id }} className="flex flex-col hover:underline">
      <span className="font-medium">{person.name}</span>
      <span className="text-xs text-muted-foreground">{person.email}</span>
    </Link>
  )
}

/** The recorded context, indented; text that is not JSON is shown as it is. */
function prettyContext(raw: string | null): string | null {
  if (!raw) return null
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

/** One event in full, opened from a row of the log. */
export function AuditDetail({ event, onClose }: { event: AuditEvent | null; onClose: () => void }) {
  const context = event ? prettyContext(event.event_context) : null
  return (
    <Sheet open={event !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        {event ? (
          <>
            <SheetHeader>
              <SheetTitle>{eventLabel(event.event_type)}</SheetTitle>
              <SheetDescription className="font-mono text-xs">{event.event_type}</SheetDescription>
            </SheetHeader>
            <dl className="flex flex-col px-4 pb-6">
              <Row label="시각">{formatDateTime(event.occurred_at)}</Row>
              <Row label="결과">
                <Badge variant={event.outcome === 'failure' ? 'destructive' : event.outcome === 'success' ? 'secondary' : 'outline'}>
                  {event.outcome === 'success' ? '성공' : event.outcome === 'failure' ? '실패' : '시작'}
                </Badge>
              </Row>
              <Row label="행위자">
                <PersonRow id={event.actor_user_id} person={event.actor} />
              </Row>
              <Row label="대상">
                {event.target_user_id || event.actor_user_id ? <PersonRow id={event.target_user_id} person={event.target} /> : <span className="text-muted-foreground">없음</span>}
              </Row>
              <Row label="IP">{event.client_ip ?? '기록 없음'}</Row>
              <Row label="요청 경로">
                <span className="font-mono text-xs">{event.request_path}</span>
              </Row>
              <Row label="이벤트 ID">
                <span className="flex items-center gap-2">
                  <span className="font-mono text-xs">{event.id}</span>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="이벤트 ID 복사"
                    onClick={async () => {
                      await navigator.clipboard.writeText(event.id)
                      toast.success('ID를 복사했습니다.')
                    }}
                  >
                    <CopyIcon />
                  </Button>
                </span>
              </Row>
              <Row label="기록된 상세 내용">
                {context ? <pre className="max-h-80 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs leading-relaxed">{context}</pre> : <span className="text-muted-foreground">추가로 기록된 내용이 없습니다.</span>}
              </Row>
            </dl>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  )
}
