import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CopyIcon, PlusIcon, TagsIcon, Trash2Icon, UserMinusIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
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
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { ROLE_LABELS, type Account } from '@/lib/accounts'
import { AttributesDialog, type AttributeTarget } from './attributes-dialog'
import { formatDateTime } from '@/lib/format'

type Member = { userId: string; role: 'admin' | 'member'; grantedAt: string }
type Invitation = {
  tokenPrefix: string
  role: 'admin' | 'member'
  createdAt: string
  expiresAt: string
  status: 'pending' | 'consumed' | 'expired'
  deliverTo: string | null
}
type DirectoryUser = { id: string; name: string; email: string }

const listKey = ['admin', 'accounts'] as const

function reason(cause: unknown, fallback: string) {
  return cause instanceof ApiError ? cause.message : fallback
}

export function AccountsAdminPage() {
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [openId, setOpenId] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Account | null>(null)
  const [attrTarget, setAttrTarget] = useState<AttributeTarget | null>(null)

  const { data, isPending, error } = useQuery({
    queryKey: listKey,
    queryFn: () => apiFetch<{ accounts: Account[] }>('/api/admin/accounts?limit=100'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/accounts/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      setPendingDelete(null)
      toast.success('계정을 삭제했습니다.')
      await queryClient.invalidateQueries({ queryKey: listKey })
    },
    onError: (cause: unknown) => {
      setPendingDelete(null)
      toast.error(reason(cause, '계정을 삭제하지 못했습니다.'))
    },
  })

  const accounts = data?.accounts ?? []

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">계정</h1>
        <Button onClick={() => setCreateOpen(true)}>
          <PlusIcon data-icon="inline-start" />계정 추가
        </Button>
      </div>
      <p className="-mt-3 text-sm text-muted-foreground">
        계정은 조직 단위의 작업 공간입니다. 사용자는 여러 계정에 속할 수 있고, 앱 접근 정책이 특정 계정의 멤버만 허용하도록 제한할 수 있습니다.
      </p>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>계정 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 3 }, (_, index) => (
            <Skeleton key={index} className="h-12 rounded-md" />
          ))}
        </div>
      ) : accounts.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>계정이 없습니다</EmptyTitle>
            <EmptyDescription>계정을 만들면 만든 사람이 첫 관리자 멤버가 됩니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>이름</TableHead>
                <TableHead>설명</TableHead>
                <TableHead>만든 날짜</TableHead>
                <TableHead className="w-32 sticky right-0 bg-background" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {accounts.map((account) => (
                <TableRow key={account.id}>
                  <TableCell className="font-medium">{account.name}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">{account.description || '—'}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(account.createdAt)}</TableCell>
                  <TableCell className="whitespace-nowrap sticky right-0 bg-background">
                    <Button variant="outline" size="sm" onClick={() => setOpenId(account.id)}>
                      관리
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`${account.name} 속성`}
                      onClick={() => setAttrTarget({ type: 'account', id: account.id, label: account.name })}
                    >
                      <TagsIcon />
                    </Button>
                    <Button variant="ghost" size="icon-sm" aria-label={`${account.name} 삭제`} onClick={() => setPendingDelete(account)}>
                      <Trash2Icon />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <CreateAccountDialog open={createOpen} onOpenChange={setCreateOpen} />
      <ManageDialog accountId={openId} onClose={() => setOpenId(null)} />
      <AttributesDialog target={attrTarget} onClose={() => setAttrTarget(null)} />

      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{pendingDelete?.name} 계정을 삭제할까요?</AlertDialogTitle>
            <AlertDialogDescription>
              멤버 목록, 초대, 세션별 활성 계정 선택, 계정 속성이 함께 지워집니다. 이 계정을 조건으로 쓰는 앱 접근 정책은 계정이 없어진 상태로 남습니다.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>취소</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={(event) => {
                event.preventDefault()
                if (pendingDelete) remove.mutate(pendingDelete.id)
              }}
            >
              삭제
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function CreateAccountDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: () =>
      apiFetch('/api/admin/accounts', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim(), description: description.trim() }),
      }),
    onSuccess: async () => {
      toast.success('계정을 만들었습니다.')
      setName('')
      setDescription('')
      setFailure(null)
      onOpenChange(false)
      await queryClient.invalidateQueries({ queryKey: listKey })
    },
    onError: (cause: unknown) => {
      if (cause instanceof ApiError && cause.status === 409) setFailure('같은 이름의 계정이 이미 있습니다.')
      else if (cause instanceof ApiError && cause.status === 400) setFailure('이름은 영문, 숫자, 점, 밑줄, 하이픈으로 64자까지 쓸 수 있습니다.')
      else setFailure('계정을 만들지 못했습니다.')
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    create.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !create.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>계정 추가</DialogTitle>
          <DialogDescription>만든 사람이 이 계정의 첫 관리자 멤버가 됩니다.</DialogDescription>
        </DialogHeader>
        <form id="create-account" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="account-name">이름</FieldLabel>
              <Input id="account-name" autoComplete="off" spellCheck={false} maxLength={64} value={name} onChange={(event) => setName(event.target.value)} />
              <FieldDescription>영문, 숫자, 점, 밑줄, 하이픈. 예: acme-korea</FieldDescription>
              {failure ? <FieldError>{failure}</FieldError> : null}
            </Field>
            <Field>
              <FieldLabel htmlFor="account-description">설명</FieldLabel>
              <Input id="account-description" maxLength={512} value={description} onChange={(event) => setDescription(event.target.value)} />
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            취소
          </Button>
          <Button type="submit" form="create-account" disabled={create.isPending || !name.trim()}>
            {create.isPending ? <Spinner data-icon="inline-start" /> : null}
            추가
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ManageDialog({ accountId, onClose }: { accountId: string | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const detailKey = ['admin', 'account', accountId] as const
  const invitesKey = ['admin', 'account-invitations', accountId] as const
  const [issued, setIssued] = useState<string | null>(null)
  const [inviteRole, setInviteRole] = useState<'member' | 'admin'>('member')
  const [term, setTerm] = useState('')
  const [search, setSearch] = useState('')

  const detail = useQuery({
    queryKey: detailKey,
    enabled: accountId !== null,
    queryFn: () => apiFetch<{ account: Account; members: Member[] }>(`/api/admin/accounts/${accountId}`),
  })
  const invitations = useQuery({
    queryKey: invitesKey,
    enabled: accountId !== null,
    queryFn: async () => (await apiFetch<{ invitations: Invitation[] }>(`/api/admin/accounts/${accountId}/invitations`)).invitations,
  })
  const users = useQuery({
    queryKey: ['admin', 'account-users', search],
    enabled: accountId !== null,
    queryFn: async () => {
      const result = await authClient.admin.listUsers({
        query: {
          limit: 100,
          sortBy: 'createdAt',
          sortDirection: 'desc',
          ...(search ? { searchField: 'email' as const, searchOperator: 'contains' as const, searchValue: search } : {}),
        },
      })
      if (result.error) throw new Error('users')
      return (result.data as { users: DirectoryUser[] }).users
    },
  })

  const refresh = () => queryClient.invalidateQueries({ queryKey: detailKey })
  const refreshInvites = () => queryClient.invalidateQueries({ queryKey: invitesKey })

  const add = useMutation({
    mutationFn: (userId: string) =>
      apiFetch(`/api/admin/accounts/${accountId}/members`, { method: 'POST', body: JSON.stringify({ userId, role: 'member' }) }),
    onSuccess: refresh,
    onError: (cause: unknown) => toast.error(reason(cause, '멤버를 추가하지 못했습니다.')),
  })
  const drop = useMutation({
    mutationFn: (userId: string) => apiFetch(`/api/admin/accounts/${accountId}/members/${userId}`, { method: 'DELETE' }),
    onSuccess: refresh,
    onError: (cause: unknown) => toast.error(reason(cause, '멤버를 내보내지 못했습니다.')),
  })
  const setRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: 'admin' | 'member' }) =>
      apiFetch(`/api/admin/accounts/${accountId}/members/${userId}`, { method: 'PATCH', body: JSON.stringify({ role }) }),
    onSuccess: refresh,
    onError: (cause: unknown) => toast.error(reason(cause, '역할을 바꾸지 못했습니다.')),
  })
  const invite = useMutation({
    mutationFn: () =>
      apiFetch<{ invitation: { token: string } }>(`/api/admin/accounts/${accountId}/invitations`, {
        method: 'POST',
        body: JSON.stringify({ role: inviteRole }),
      }),
    onSuccess: async (result) => {
      setIssued(result.invitation.token)
      await refreshInvites()
    },
    onError: () => toast.error('초대를 만들지 못했습니다.'),
  })
  const people = new Map((users.data ?? []).map((user) => [user.id, user]))
  const memberIds = new Set(detail.data?.members.map((member) => member.userId))
  const candidates = (users.data ?? []).filter((user) => !memberIds.has(user.id))

  return (
    <Dialog
      open={accountId !== null}
      onOpenChange={(open) => {
        if (!open) {
          setIssued(null)
          onClose()
        }
      }}
    >
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{detail.data?.account.name ?? '계정'}</DialogTitle>
          <DialogDescription>{detail.data?.account.description || '멤버와 초대를 관리합니다.'}</DialogDescription>
        </DialogHeader>

        {detail.error ? (
          <Alert variant="destructive">
            <AlertDescription>계정 정보를 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : detail.isPending ? (
          <Skeleton className="h-40 rounded-lg" />
        ) : (
          <div className="flex max-h-[60vh] flex-col gap-6 overflow-y-auto pr-1">
            <div className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">
                멤버 <Badge variant="secondary">{detail.data.members.length}</Badge>
              </h3>
              <ItemGroup className="gap-2">
                {detail.data.members.map((member) => {
                  const person = people.get(member.userId)
                  return (
                    <Item key={member.userId} variant="muted" size="sm">
                      <ItemContent>
                        <ItemTitle>{person?.name ?? member.userId}</ItemTitle>
                        <ItemDescription>{person?.email ?? formatDateTime(member.grantedAt)}</ItemDescription>
                      </ItemContent>
                      <ItemActions>
                        <Select
                          value={member.role}
                          onValueChange={(role) => setRole.mutate({ userId: member.userId, role: role as 'admin' | 'member' })}
                        >
                          <SelectTrigger size="sm" className="w-24" aria-label={`${person?.email ?? member.userId} 역할`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectGroup>
                              <SelectItem value="admin">{ROLE_LABELS.admin}</SelectItem>
                              <SelectItem value="member">{ROLE_LABELS.member}</SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`${person?.email ?? member.userId} 내보내기`}
                          disabled={drop.isPending}
                          onClick={() => drop.mutate(member.userId)}
                        >
                          <UserMinusIcon />
                        </Button>
                      </ItemActions>
                    </Item>
                  )
                })}
              </ItemGroup>
            </div>

            <div className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">멤버 추가</h3>
              <form
                className="flex gap-2"
                onSubmit={(event) => {
                  event.preventDefault()
                  setSearch(term.trim())
                }}
              >
                <Input aria-label="이메일 검색" placeholder="이메일로 검색" value={term} onChange={(event) => setTerm(event.target.value)} />
                <Button type="submit" variant="outline">검색</Button>
              </form>
              {candidates.length === 0 ? (
                <p className="text-sm text-muted-foreground">추가할 수 있는 사용자가 없습니다.</p>
              ) : (
                <ItemGroup className="max-h-40 gap-2 overflow-y-auto">
                  {candidates.map((user) => (
                    <Item key={user.id} variant="outline" size="sm">
                      <ItemContent>
                        <ItemTitle>{user.name}</ItemTitle>
                        <ItemDescription>{user.email}</ItemDescription>
                      </ItemContent>
                      <ItemActions>
                        <Button variant="outline" size="sm" disabled={add.isPending} onClick={() => add.mutate(user.id)}>
                          <PlusIcon data-icon="inline-start" />추가
                        </Button>
                      </ItemActions>
                    </Item>
                  ))}
                </ItemGroup>
              )}
            </div>

            <div className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">초대 코드</h3>
              <p className="text-sm text-muted-foreground">
                코드를 받은 사람은 "계정" 화면에서 입력해 참여합니다. 코드는 한 번만 쓸 수 있고, 만든 직후 한 번만 볼 수 있습니다.
              </p>
              <div className="flex items-center gap-2">
                <Select value={inviteRole} onValueChange={(role) => setInviteRole(role as 'admin' | 'member')}>
                  <SelectTrigger size="sm" className="w-28" aria-label="초대 역할">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="member">{ROLE_LABELS.member}</SelectItem>
                      <SelectItem value="admin">{ROLE_LABELS.admin}</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
                <Button variant="outline" size="sm" disabled={invite.isPending} onClick={() => invite.mutate()}>
                  {invite.isPending ? <Spinner data-icon="inline-start" /> : null}
                  초대 코드 만들기
                </Button>
              </div>
              {issued ? (
                <div className="flex items-center gap-2">
                  <code className="min-w-0 flex-1 truncate rounded-md bg-muted px-2 py-1.5 font-mono text-xs">{issued}</code>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={async () => {
                      await navigator.clipboard.writeText(issued).catch(() => undefined)
                      toast.success('복사했습니다.')
                    }}
                  >
                    <CopyIcon data-icon="inline-start" />복사
                  </Button>
                </div>
              ) : null}
              {(invitations.data ?? []).length > 0 ? (
                <ItemGroup className="gap-2">
                  {invitations.data!.map((entry) => (
                    <Item key={entry.tokenPrefix + entry.createdAt} variant="muted" size="sm">
                      <ItemContent>
                        <ItemTitle>
                          <span className="font-mono">{entry.tokenPrefix}</span>
                          <Badge variant="outline">{ROLE_LABELS[entry.role]}</Badge>
                        </ItemTitle>
                        <ItemDescription>
                          {entry.status === 'pending' ? `${formatDateTime(entry.expiresAt)}까지` : entry.status === 'consumed' ? '사용됨' : '기한 지남'}
                        </ItemDescription>
                      </ItemContent>
                    </Item>
                  ))}
                </ItemGroup>
              ) : null}
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>닫기</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
