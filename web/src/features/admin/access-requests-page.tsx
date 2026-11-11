import { ConfirmAction } from '@/components/confirm-dialog'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, Trash2Icon } from 'lucide-react'
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
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemTitle } from '@/components/ui/item'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { formatDuration, STATUS_LABELS, subjectLabel } from '@/lib/access-requests'
import { formatDateTime } from '@/lib/format'

type Rule = { id: string; name: string; minReviewers: number; notifyMode: 'all' | 'random'; reviewerUsers: string[]; reviewerGroups: string[] }
type Binding = {
  id: string
  subject: string
  ruleId: string
  pendingExpirySeconds: number
  maxGrantedExpirySeconds: number
}
type AdminRequest = {
  id: string
  subject: string
  userId: string
  status: keyof typeof STATUS_LABELS
  justification: string
  grantedExpiresAt: string | null
  createdAt: string
}
type Group = { id: string; name: string }
type UserRow = { id: string; name: string; email: string }

const rulesKey = ['admin', 'request-rules'] as const
const bindingsKey = ['admin', 'request-bindings'] as const
const requestsKey = ['admin', 'access-requests'] as const

function message(cause: unknown, fallback: string) {
  return cause instanceof ApiError ? cause.message : fallback
}

export function AccessRequestsAdminPage() {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-8">
      <h1 className="text-2xl font-semibold">접근 요청 관리</h1>
      <RulesSection />
      <BindingsSection />
      <RequestsSection />
    </div>
  )
}

function useRules() {
  return useQuery({
    queryKey: rulesKey,
    queryFn: async () => (await apiFetch<{ rules: Rule[] }>('/api/admin/access-request-rules')).rules,
  })
}

function RulesSection() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useRules()
  const [createOpen, setCreateOpen] = useState(false)

  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/access-request-rules/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('규칙을 삭제했습니다.')
      await queryClient.invalidateQueries({ queryKey: rulesKey })
    },
    onError: (cause: unknown) => toast.error(message(cause, '규칙이 앱에 연결돼 있으면 삭제할 수 없습니다.')),
  })

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-medium text-muted-foreground">검토 규칙</h2>
          <p className="text-sm text-muted-foreground">누가, 몇 명이 요청을 승인하는지 정합니다.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setCreateOpen(true)}>
          <PlusIcon data-icon="inline-start" />규칙 추가
        </Button>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>규칙을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-20 rounded-xl" />
      ) : data!.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>검토 규칙이 없습니다</EmptyTitle>
            <EmptyDescription>규칙을 만들고 앱에 연결하면 사용자가 그 앱의 접근을 요청할 수 있습니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ItemGroup className="gap-2">
          {data!.map((rule) => (
            <Item key={rule.id} variant="outline">
              <ItemContent>
                <ItemTitle>{rule.name}</ItemTitle>
                <ItemDescription>
                  검토자 {rule.reviewerUsers.length}명 · 그룹 {rule.reviewerGroups.length}개 · {rule.minReviewers}명 승인 필요
                </ItemDescription>
              </ItemContent>
              <ItemActions>
                <ConfirmAction
                  title="이 규칙을 삭제할까요?"
                  description="이 규칙에 연결된 앱은 접근 요청을 받을 수 없게 됩니다. 이미 대기 중인 요청은 남을 수 있습니다."
                  details={[{ label: '규칙', value: rule.name }]}
                  confirmLabel="삭제"
                  onConfirm={() => remove.mutate(rule.id)}
                >
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`${rule.name} 삭제`}
                    disabled={remove.isPending}
                  >
                    <Trash2Icon />
                  </Button>
                </ConfirmAction>
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
      <CreateRuleDialog open={createOpen} onOpenChange={setCreateOpen} />
    </section>
  )
}

function CreateRuleDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [min, setMin] = useState('1')
  const [users, setUsers] = useState<string[]>([])
  const [groups, setGroups] = useState<string[]>([])
  const [failure, setFailure] = useState<string | null>(null)

  const userList = useQuery({
    queryKey: ['admin', 'request-users'],
    enabled: open,
    queryFn: async () => {
      const result = await authClient.admin.listUsers({ query: { limit: 100, sortBy: 'createdAt', sortDirection: 'desc' } })
      if (result.error) throw new Error('users')
      return (result.data as { users: UserRow[] }).users
    },
  })
  const groupList = useQuery({
    queryKey: ['admin', 'groups'],
    enabled: open,
    queryFn: () => apiFetch<{ groups: Group[] }>('/api/admin/directory-groups?limit=100'),
  })

  const create = useMutation({
    mutationFn: () =>
      apiFetch('/api/admin/access-request-rules', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim(), minReviewers: Number(min), reviewerUsers: users, reviewerGroups: groups }),
      }),
    onSuccess: async () => {
      toast.success('규칙을 만들었습니다.')
      setName('')
      setMin('1')
      setUsers([])
      setGroups([])
      setFailure(null)
      onOpenChange(false)
      await queryClient.invalidateQueries({ queryKey: rulesKey })
    },
    onError: (cause: unknown) => setFailure(message(cause, '규칙을 만들지 못했습니다.')),
  })

  const toggle = (list: string[], set: (next: string[]) => void, id: string, on: boolean) =>
    set(on ? [...list, id] : list.filter((entry) => entry !== id))

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    if (users.length + groups.length === 0) {
      setFailure('검토자나 검토 그룹을 하나 이상 고르세요.')
      return
    }
    create.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !create.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>검토 규칙 추가</DialogTitle>
          <DialogDescription>요청자는 자기 요청을 검토할 수 없습니다.</DialogDescription>
        </DialogHeader>
        <form id="create-rule" onSubmit={submit} noValidate className="max-h-[60vh] overflow-y-auto pr-1">
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="rule-name">이름</FieldLabel>
              <Input id="rule-name" autoComplete="off" spellCheck={false} maxLength={64} value={name} onChange={(event) => setName(event.target.value)} />
              <FieldDescription>영문, 숫자, 점, 밑줄, 하이픈. 예: it-approvers</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="rule-min">필요한 승인 수</FieldLabel>
              <Select value={min} onValueChange={setMin}>
                <SelectTrigger id="rule-min" className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {[1, 2, 3, 4, 5].map((count) => (
                      <SelectItem key={count} value={String(count)}>
                        {count}명
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <FieldSet>
              <FieldLegend variant="label">검토 그룹</FieldLegend>
              {(groupList.data?.groups ?? []).length === 0 ? (
                <FieldDescription>그룹이 없습니다.</FieldDescription>
              ) : (
                groupList.data!.groups.map((group) => (
                  <Item key={group.id} variant="outline" size="sm">
                    <ItemContent>
                      <ItemTitle>{group.name}</ItemTitle>
                    </ItemContent>
                    <ItemActions>
                      <Switch aria-label={`${group.name} 그룹을 검토자로`} checked={groups.includes(group.id)} onCheckedChange={(on) => toggle(groups, setGroups, group.id, on)} />
                    </ItemActions>
                  </Item>
                ))
              )}
            </FieldSet>
            <FieldSet>
              <FieldLegend variant="label">검토자</FieldLegend>
              {(userList.data ?? []).map((user) => (
                <Item key={user.id} variant="outline" size="sm">
                  <ItemContent>
                    <ItemTitle>{user.name}</ItemTitle>
                    <ItemDescription>{user.email}</ItemDescription>
                  </ItemContent>
                  <ItemActions>
                    <Switch aria-label={`${user.email}을 검토자로`} checked={users.includes(user.id)} onCheckedChange={(on) => toggle(users, setUsers, user.id, on)} />
                  </ItemActions>
                </Item>
              ))}
            </FieldSet>
            {failure ? (
              <Field data-invalid>
                <FieldError>{failure}</FieldError>
              </Field>
            ) : null}
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            취소
          </Button>
          <Button type="submit" form="create-rule" disabled={create.isPending || !name.trim()}>
            {create.isPending ? <Spinner data-icon="inline-start" /> : null}
            추가
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function BindingsSection() {
  const queryClient = useQueryClient()
  const rules = useRules()
  const { data, isPending, error } = useQuery({
    queryKey: bindingsKey,
    queryFn: async () => (await apiFetch<{ bindings: Binding[] }>('/api/admin/access-request-bindings')).bindings,
  })
  const [createOpen, setCreateOpen] = useState(false)

  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/access-request-bindings/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('요청 설정을 해제했습니다.')
      await queryClient.invalidateQueries({ queryKey: bindingsKey })
    },
    onError: () => toast.error('해제하지 못했습니다.'),
  })

  const ruleName = (id: string) => rules.data?.find((rule) => rule.id === id)?.name ?? '—'

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-medium text-muted-foreground">요청을 받는 앱</h2>
          <p className="text-sm text-muted-foreground">규칙을 앱에 연결하면 사용자의 접근 요청 화면에 그 앱이 나타납니다.</p>
        </div>
        <Button variant="outline" size="sm" disabled={(rules.data ?? []).length === 0} onClick={() => setCreateOpen(true)}>
          <PlusIcon data-icon="inline-start" />앱 연결
        </Button>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>연결된 앱을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-20 rounded-xl" />
      ) : data!.length === 0 ? (
        <p className="text-sm text-muted-foreground">연결된 앱이 없습니다.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>앱</TableHead>
                <TableHead>규칙</TableHead>
                <TableHead>최대 사용 기간</TableHead>
                <TableHead>검토 대기</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data!.map((binding) => (
                <TableRow key={binding.id}>
                  <TableCell className="font-mono text-xs">{binding.subject}</TableCell>
                  <TableCell>{ruleName(binding.ruleId)}</TableCell>
                  <TableCell>{formatDuration(binding.maxGrantedExpirySeconds)}</TableCell>
                  <TableCell>{formatDuration(binding.pendingExpirySeconds)}</TableCell>
                  <TableCell>
                    <ConfirmAction
                      title="이 연결을 해제할까요?"
                      description="이 앱은 더 이상 이 규칙으로 접근 요청을 받지 않습니다."
                      details={[{ label: '앱', value: binding.subject }, { label: '규칙', value: ruleName(binding.ruleId) }]}
                      confirmLabel="해제"
                      onConfirm={() => remove.mutate(binding.id)}
                    >
                      <Button variant="ghost" size="icon-sm" aria-label={`${binding.subject} 연결 해제`}>
                        <Trash2Icon />
                      </Button>
                    </ConfirmAction>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <CreateBindingDialog open={createOpen} onOpenChange={setCreateOpen} rules={rules.data ?? []} />
    </section>
  )
}

function CreateBindingDialog({
  open,
  onOpenChange,
  rules,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  rules: Rule[]
}) {
  const queryClient = useQueryClient()
  const [subject, setSubject] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [maxHours, setMaxHours] = useState('24')
  const [failure, setFailure] = useState<string | null>(null)

  const apps = useQuery({
    queryKey: ['admin', 'applications'],
    enabled: open,
    queryFn: async () => (await apiFetch<{ applications: Array<{ slug: string; name: string }> }>('/api/admin/applications')).applications,
  })

  const create = useMutation({
    mutationFn: () =>
      apiFetch('/api/admin/access-request-bindings', {
        method: 'POST',
        body: JSON.stringify({ subject, ruleId, maxGrantedExpirySeconds: Number(maxHours) * 3600 }),
      }),
    onSuccess: async () => {
      toast.success('앱을 연결했습니다.')
      setSubject('')
      setFailure(null)
      onOpenChange(false)
      await queryClient.invalidateQueries({ queryKey: bindingsKey })
    },
    onError: (cause: unknown) => setFailure(message(cause, '연결하지 못했습니다.')),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    const hours = Number(maxHours)
    if (!Number.isInteger(hours) || hours < 1 || hours > 720) {
      setFailure('최대 사용 기간은 1시간에서 720시간(30일) 사이로 입력하세요.')
      return
    }
    create.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !create.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>요청을 받을 앱 연결</DialogTitle>
          <DialogDescription>승인되면 정한 기간 동안만 앱을 열 수 있습니다. 앱 접근 정책의 그룹 제한을 넘어서는 일시 허용입니다.</DialogDescription>
        </DialogHeader>
        <form id="create-binding" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="binding-app">앱</FieldLabel>
              <Select value={subject} onValueChange={setSubject}>
                <SelectTrigger id="binding-app" className="w-full">
                  <SelectValue placeholder="앱 선택" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {(apps.data ?? []).map((app) => (
                      <SelectItem key={app.slug} value={`app:${app.slug}`}>
                        {app.name}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel htmlFor="binding-rule">검토 규칙</FieldLabel>
              <Select value={ruleId} onValueChange={setRuleId}>
                <SelectTrigger id="binding-rule" className="w-full">
                  <SelectValue placeholder="규칙 선택" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {rules.map((rule) => (
                      <SelectItem key={rule.id} value={rule.id}>
                        {rule.name}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="binding-hours">최대 사용 기간</FieldLabel>
              <div className="flex items-center gap-2">
                <Input id="binding-hours" type="number" inputMode="numeric" className="w-28" min={1} max={720} value={maxHours} onChange={(event) => setMaxHours(event.target.value)} />
                <span className="text-sm text-muted-foreground">시간</span>
              </div>
              {failure ? <FieldError>{failure}</FieldError> : null}
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            취소
          </Button>
          <Button type="submit" form="create-binding" disabled={create.isPending || !subject || !ruleId}>
            {create.isPending ? <Spinner data-icon="inline-start" /> : null}
            연결
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function RequestsSection() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useQuery({
    queryKey: requestsKey,
    queryFn: async () => (await apiFetch<{ requests: AdminRequest[] }>('/api/admin/access-requests')).requests,
  })

  const revoke = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/access-requests/${id}/revoke`, { method: 'POST', body: '{}' }),
    onSuccess: async () => {
      toast.success('허용을 회수했습니다.')
      await queryClient.invalidateQueries({ queryKey: requestsKey })
    },
    onError: () => toast.error('회수하지 못했습니다.'),
  })

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium text-muted-foreground">전체 요청</h2>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>요청 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-20 rounded-xl" />
      ) : data!.length === 0 ? (
        <p className="text-sm text-muted-foreground">아직 요청이 없습니다.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>앱</TableHead>
                <TableHead>사유</TableHead>
                <TableHead>상태</TableHead>
                <TableHead>요청일</TableHead>
                <TableHead className="w-20" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data!.map((request) => (
                <TableRow key={request.id}>
                  <TableCell className="font-medium">{subjectLabel(request.subject, null)}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">{request.justification}</TableCell>
                  <TableCell>
                    <Badge variant={request.status === 'approved' ? 'default' : 'secondary'}>{STATUS_LABELS[request.status]}</Badge>
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(request.createdAt)}</TableCell>
                  <TableCell>
                    {request.status === 'approved' ? (
                      <ConfirmAction
                        title="승인한 접근을 회수할까요?"
                        description="이 사용자는 바로 해당 앱 접근을 잃습니다. 이미 앱에서 열어 둔 세션은 앱이 확인할 때까지 남을 수 있습니다."
                        confirmLabel="회수"
                        onConfirm={() => revoke.mutate(request.id)}
                      >
                        <Button variant="outline" size="sm" disabled={revoke.isPending}>
                          회수
                        </Button>
                      </ConfirmAction>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  )
}
