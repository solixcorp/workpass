import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { MailIcon, PlusIcon, Trash2Icon, WebhookIcon } from 'lucide-react'
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
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemMedia, ItemTitle } from '@/components/ui/item'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import type { NotificationRule, Transport } from '@/lib/policies'

const rulesKey = ['admin', 'notification-rules'] as const

export function useNotificationRules(enabled = true) {
  return useQuery({
    queryKey: rulesKey,
    enabled,
    queryFn: async () => (await apiFetch<{ rules: NotificationRule[] }>('/api/admin/notification-rules')).rules,
  })
}

type Row = { kind: 'webhook' | 'email'; value: string }

/** Where an event notification goes. Which events trigger it is set by binding an event-matcher policy. */
export function NotificationRules() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useNotificationRules()
  const [open, setOpen] = useState(false)

  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/notification-rules/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('알림 규칙을 삭제했습니다.')
      await queryClient.invalidateQueries({ queryKey: rulesKey })
    },
    onError: () => toast.error('삭제하지 못했습니다.'),
  })

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-medium text-muted-foreground">알림 규칙</h2>
          <p className="text-sm text-muted-foreground">
            알릴 곳(웹훅, 이메일)을 정합니다. 어떤 이벤트에 알릴지는 위에서 "이벤트 매처" 정책을 만든 뒤, 연결 추가에서 검사할 때를
            "알림 규칙"으로 하고 이 규칙을 골라 연결합니다.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
          <PlusIcon data-icon="inline-start" />규칙 추가
        </Button>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>알림 규칙을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-20 rounded-xl" />
      ) : data!.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>알림 규칙이 없습니다</EmptyTitle>
            <EmptyDescription>예를 들어 관리자 로그인 실패가 날 때 보안 담당자 메일로 알리는 규칙을 만들 수 있습니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ItemGroup className="gap-2">
          {data!.map((rule) => (
            <Item key={rule.id} variant="outline">
              <ItemMedia variant="icon">{rule.transports[0]?.kind === 'email' ? <MailIcon /> : <WebhookIcon />}</ItemMedia>
              <ItemContent>
                <ItemTitle>
                  {rule.name}
                  {!rule.enabled ? <Badge variant="outline">꺼짐</Badge> : null}
                </ItemTitle>
                <ItemDescription>
                  {rule.transports.map((transport) => (transport.kind === 'email' ? transport.to : transport.url)).join(' · ')}
                </ItemDescription>
                <ItemDescription>
                  규칙 ID <code className="font-mono">{rule.id}</code>
                </ItemDescription>
              </ItemContent>
              <ItemActions>
                <Button variant="ghost" size="icon-sm" aria-label={`${rule.name} 삭제`} disabled={remove.isPending} onClick={() => remove.mutate(rule.id)}>
                  <Trash2Icon />
                </Button>
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
      <CreateDialog open={open} onOpenChange={setOpen} />
    </section>
  )
}

function CreateDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [rows, setRows] = useState<Row[]>([{ kind: 'email', value: '' }])
  const [failure, setFailure] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: (transports: Transport[]) =>
      apiFetch('/api/admin/notification-rules', { method: 'POST', body: JSON.stringify({ name: name.trim(), transports }) }),
    onSuccess: async () => {
      toast.success('알림 규칙을 만들었습니다.')
      setName('')
      setRows([{ kind: 'email', value: '' }])
      setFailure(null)
      onOpenChange(false)
      await queryClient.invalidateQueries({ queryKey: rulesKey })
    },
    onError: (cause: unknown) => {
      if (cause instanceof ApiError && cause.status === 409) setFailure('같은 이름의 규칙이 이미 있습니다.')
      else setFailure(cause instanceof ApiError ? cause.message : '만들지 못했습니다.')
    },
  })

  function update(index: number, patch: Partial<Row>) {
    setRows((current) => current.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    const transports: Transport[] = []
    for (const row of rows) {
      const value = row.value.trim()
      if (row.kind === 'webhook') {
        if (!/^https:\/\/\S+$/.test(value)) {
          setFailure('웹훅 주소는 https://로 시작해야 합니다.')
          return
        }
        transports.push({ kind: 'webhook', url: value })
      } else {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          setFailure('이메일 주소 형식이 맞지 않습니다.')
          return
        }
        transports.push({ kind: 'email', to: value })
      }
    }
    create.mutate(transports)
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !create.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>알림 규칙 추가</DialogTitle>
          <DialogDescription>이벤트가 조건에 맞으면 아래 전송 수단으로 알립니다. 최대 10개.</DialogDescription>
        </DialogHeader>
        <form id="notification-rule" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="notification-name">이름</FieldLabel>
              <Input id="notification-name" autoComplete="off" spellCheck={false} maxLength={64} value={name} onChange={(event) => setName(event.target.value)} />
              <FieldDescription>영문, 숫자, 점, 밑줄, 하이픈. 예: security-alerts</FieldDescription>
            </Field>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel>전송 수단</FieldLabel>
              <div className="flex flex-col gap-2">
                {rows.map((row, index) => (
                  <div key={index} className="flex items-center gap-2">
                    <Select value={row.kind} onValueChange={(kind) => update(index, { kind: kind as Row['kind'], value: '' })}>
                      <SelectTrigger className="w-28" aria-label={`전송 수단 ${index + 1} 종류`}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="email">이메일</SelectItem>
                          <SelectItem value="webhook">웹훅</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                    <Input
                      aria-label={`전송 수단 ${index + 1} 주소`}
                      autoComplete="off"
                      spellCheck={false}
                      placeholder={row.kind === 'email' ? 'security@example.com' : 'https://hooks.example.com/…'}
                      className="flex-1"
                      value={row.value}
                      onChange={(event) => update(index, { value: event.target.value })}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`전송 수단 ${index + 1} 삭제`}
                      disabled={rows.length === 1}
                      onClick={() => setRows((current) => current.filter((_, i) => i !== index))}
                    >
                      <Trash2Icon />
                    </Button>
                  </div>
                ))}
              </div>
              <div>
                <Button type="button" variant="outline" size="sm" disabled={rows.length >= 10} onClick={() => setRows((current) => [...current, { kind: 'email', value: '' }])}>
                  <PlusIcon data-icon="inline-start" />전송 수단 추가
                </Button>
              </div>
              {failure ? <FieldError>{failure}</FieldError> : null}
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            취소
          </Button>
          <Button type="submit" form="notification-rule" disabled={create.isPending || !name.trim()}>
            {create.isPending ? <Spinner data-icon="inline-start" /> : null}
            추가
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
