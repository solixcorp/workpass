import { ConfirmAction } from '@/components/confirm-dialog'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckIcon, XIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemTitle } from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'
import {
  formatDuration,
  STATUS_LABELS,
  subjectLabel,
  type AccessRequest,
  type Requestable,
} from '@/lib/access-requests'
import { formatDateTime } from '@/lib/format'

const requestableKey = ['access', 'requestable'] as const
const mineKey = ['access', 'mine'] as const
const reviewsKey = ['access', 'reviews'] as const

function refreshAll(queryClient: ReturnType<typeof useQueryClient>) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: requestableKey }),
    queryClient.invalidateQueries({ queryKey: mineKey }),
    queryClient.invalidateQueries({ queryKey: reviewsKey }),
    queryClient.invalidateQueries({ queryKey: ['applications'] }),
  ])
}

export function RequestsPage() {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-8">
      <h1 className="text-2xl font-semibold">접근 요청</h1>
      <ReviewSection />
      <RequestableSection />
      <MineSection />
    </div>
  )
}

function SectionError({ children }: { children: string }) {
  return (
    <Alert variant="destructive">
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  )
}

function ReviewSection() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useQuery({
    queryKey: reviewsKey,
    queryFn: async () => (await apiFetch<{ pending: AccessRequest[] }>('/api/access-requests/reviews')).pending,
  })
  const [target, setTarget] = useState<{ request: AccessRequest; decision: 'approved' | 'denied' } | null>(null)

  // The section stays out of the way for people who review nothing.
  if (!isPending && !error && data?.length === 0) return null

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium text-muted-foreground">내가 검토할 요청</h2>
      {error ? (
        <SectionError>검토할 요청을 불러오지 못했습니다.</SectionError>
      ) : isPending ? (
        <Skeleton className="h-20 rounded-xl" />
      ) : (
        <ItemGroup className="gap-2">
          {data!.map((request) => (
            <Item key={request.id} variant="outline">
              <ItemContent>
                <ItemTitle>{subjectLabel(request.subject, request.displayName)}</ItemTitle>
                <ItemDescription>{request.justification}</ItemDescription>
                <ItemDescription>
                  {formatDateTime(request.createdAt)} · 요청 기간 {formatDuration(request.requestedExpirySeconds)}
                </ItemDescription>
              </ItemContent>
              <ItemActions>
                <Button variant="outline" size="sm" onClick={() => setTarget({ request, decision: 'denied' })}>
                  <XIcon data-icon="inline-start" />거절
                </Button>
                <Button size="sm" onClick={() => setTarget({ request, decision: 'approved' })}>
                  <CheckIcon data-icon="inline-start" />승인
                </Button>
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
      <ReviewDialog target={target} onClose={() => setTarget(null)} onDone={() => refreshAll(queryClient)} />
    </section>
  )
}

function ReviewDialog({
  target,
  onClose,
  onDone,
}: {
  target: { request: AccessRequest; decision: 'approved' | 'denied' } | null
  onClose: () => void
  onDone: () => Promise<unknown>
}) {
  const [note, setNote] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const review = useMutation({
    mutationFn: () =>
      apiFetch<{ statusApplied: string | null }>(`/api/access-requests/${target!.request.id}/review`, {
        method: 'POST',
        body: JSON.stringify({ decision: target!.decision, note: note.trim() || undefined }),
      }),
    onSuccess: async (result) => {
      toast.success(
        target!.decision === 'denied'
          ? '요청을 거절했습니다.'
          : result.statusApplied
            ? '요청을 승인했습니다.'
            : '승인을 기록했습니다. 다른 검토자의 승인을 기다립니다.',
      )
      setNote('')
      setFailure(null)
      onClose()
      await onDone()
    },
    onError: (cause: unknown) =>
      setFailure(cause instanceof ApiError && cause.status === 403 ? '이 요청을 검토할 수 없습니다.' : '처리하지 못했습니다.'),
  })

  const approving = target?.decision === 'approved'

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    review.mutate()
  }

  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && !review.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {target ? subjectLabel(target.request.subject, target.request.displayName) : ''} 요청 {approving ? '승인' : '거절'}
          </DialogTitle>
          <DialogDescription>
            {approving ? '승인하면 요청한 기간 동안 사용자가 앱을 열 수 있습니다.' : '거절하면 요청이 바로 닫힙니다.'}
          </DialogDescription>
        </DialogHeader>
        <form id="review" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="review-note">메모 (선택)</FieldLabel>
              <Textarea id="review-note" rows={3} maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} />
              {failure ? <FieldError>{failure}</FieldError> : null}
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={review.isPending}>
            취소
          </Button>
          <Button type="submit" form="review" variant={approving ? 'default' : 'destructive'} disabled={review.isPending}>
            {review.isPending ? <Spinner data-icon="inline-start" /> : null}
            {approving ? '승인' : '거절'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function RequestableSection() {
  const { data, isPending, error } = useQuery({
    queryKey: requestableKey,
    queryFn: async () => (await apiFetch<{ requestable: Requestable[] }>('/api/access-requests/requestable')).requestable,
  })
  const mine = useQuery({
    queryKey: mineKey,
    queryFn: async () => (await apiFetch<{ requests: AccessRequest[] }>('/api/access-requests/me')).requests,
  })
  const [target, setTarget] = useState<Requestable | null>(null)

  const pendingSubjects = new Set(mine.data?.filter((request) => request.status === 'pending').map((request) => request.subject))

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium text-muted-foreground">요청할 수 있는 앱</h2>
      {error ? (
        <SectionError>요청할 수 있는 앱을 불러오지 못했습니다.</SectionError>
      ) : isPending ? (
        <Skeleton className="h-20 rounded-xl" />
      ) : data!.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>요청할 수 있는 앱이 없습니다</EmptyTitle>
            <EmptyDescription>관리자가 요청을 받는 앱으로 지정하면 여기에 나타납니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ItemGroup className="gap-2">
          {data!.map((item) => (
            <Item key={item.subject} variant="outline">
              <ItemContent>
                <ItemTitle>{subjectLabel(item.subject, item.displayName)}</ItemTitle>
                <ItemDescription>최대 {formatDuration(item.maxGrantedExpirySeconds)}까지 열 수 있습니다.</ItemDescription>
              </ItemContent>
              <ItemActions>
                {pendingSubjects.has(item.subject) ? (
                  <Badge variant="secondary">검토 중</Badge>
                ) : (
                  <Button variant="outline" size="sm" onClick={() => setTarget(item)}>
                    접근 요청
                  </Button>
                )}
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
      <CreateDialog target={target} onClose={() => setTarget(null)} />
    </section>
  )
}

const HOUR = 3600

function CreateDialog({ target, onClose }: { target: Requestable | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [justification, setJustification] = useState('')
  const [hours, setHours] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const max = target ? Math.floor(target.maxGrantedExpirySeconds / HOUR) : 0

  const create = useMutation({
    mutationFn: () =>
      apiFetch('/api/access-requests', {
        method: 'POST',
        body: JSON.stringify({
          subject: target!.subject,
          justification: justification.trim(),
          ...(hours ? { requestedExpirySeconds: Number(hours) * HOUR } : {}),
        }),
      }),
    onSuccess: async () => {
      toast.success('접근을 요청했습니다.')
      setJustification('')
      setHours('')
      setFailure(null)
      onClose()
      await refreshAll(queryClient)
    },
    onError: () => setFailure('요청하지 못했습니다. 이미 검토 중인 요청이 있거나 입력 값이 맞지 않습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    if (hours && (!Number.isInteger(Number(hours)) || Number(hours) < 1 || Number(hours) > max)) {
      setFailure(`기간은 1시간에서 ${max}시간 사이로 입력하세요.`)
      return
    }
    create.mutate()
  }

  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && !create.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{target ? subjectLabel(target.subject, target.displayName) : ''} 접근 요청</DialogTitle>
          <DialogDescription>검토자가 사유를 보고 승인하면, 정해진 기간 동안만 앱을 열 수 있습니다.</DialogDescription>
        </DialogHeader>
        <form id="create-request" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="request-justification">요청 사유</FieldLabel>
              <Textarea
                id="request-justification"
                rows={4}
                maxLength={2000}
                value={justification}
                onChange={(event) => setJustification(event.target.value)}
              />
            </Field>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="request-hours">필요한 기간</FieldLabel>
              <div className="flex items-center gap-2">
                <Input
                  id="request-hours"
                  type="number"
                  inputMode="numeric"
                  className="w-28"
                  min={1}
                  max={max}
                  placeholder={String(max)}
                  value={hours}
                  onChange={(event) => setHours(event.target.value)}
                />
                <span className="text-sm text-muted-foreground">시간</span>
              </div>
              <FieldDescription>비워 두면 최대 {max}시간으로 요청합니다.</FieldDescription>
              {failure ? <FieldError>{failure}</FieldError> : null}
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={create.isPending}>
            취소
          </Button>
          <Button type="submit" form="create-request" disabled={create.isPending || !justification.trim()}>
            {create.isPending ? <Spinner data-icon="inline-start" /> : null}
            요청
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function MineSection() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useQuery({
    queryKey: mineKey,
    queryFn: async () => (await apiFetch<{ requests: AccessRequest[] }>('/api/access-requests/me')).requests,
  })

  const cancel = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/access-requests/${id}/cancel`, { method: 'POST', body: '{}' }),
    onSuccess: async () => {
      toast.success('요청을 취소했습니다.')
      await refreshAll(queryClient)
    },
    onError: () => toast.error('취소하지 못했습니다.'),
  })

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium text-muted-foreground">내 요청</h2>
      {error ? (
        <SectionError>내 요청을 불러오지 못했습니다.</SectionError>
      ) : isPending ? (
        <Skeleton className="h-20 rounded-xl" />
      ) : data!.length === 0 ? (
        <p className="text-sm text-muted-foreground">아직 요청한 내역이 없습니다.</p>
      ) : (
        <ItemGroup className="gap-2">
          {data!.map((request) => (
            <Item key={request.id} variant="outline">
              <ItemContent>
                <ItemTitle>
                  {subjectLabel(request.subject, request.displayName)}
                  <Badge variant={request.status === 'approved' ? 'default' : 'secondary'}>{STATUS_LABELS[request.status]}</Badge>
                </ItemTitle>
                <ItemDescription>{request.justification}</ItemDescription>
                <ItemDescription>
                  {request.status === 'approved' && request.grantedExpiresAt
                    ? `${formatDateTime(request.grantedExpiresAt)}까지 사용할 수 있습니다.`
                    : request.status === 'pending'
                      ? `${formatDateTime(request.pendingExpiresAt)}까지 검토를 기다립니다.`
                      : formatDateTime(request.decidedAt ?? request.createdAt)}
                  {request.decisionNote ? ` · ${request.decisionNote}` : ''}
                </ItemDescription>
              </ItemContent>
              {request.status === 'pending' ? (
                <ItemActions>
                  <ConfirmAction
                    title="이 접근 요청을 취소할까요?"
                    description="취소하면 검토가 중단됩니다. 다시 필요하면 새로 요청해야 합니다."
                    details={[{ label: '앱', value: subjectLabel(request.subject, request.displayName) }]}
                    confirmLabel="요청 취소"
                    onConfirm={() => cancel.mutate(request.id)}
                  >
                    <Button variant="outline" size="sm" disabled={cancel.isPending}>
                      취소
                    </Button>
                  </ConfirmAction>
                </ItemActions>
              ) : null}
            </Item>
          ))}
        </ItemGroup>
      )}
    </section>
  )
}
