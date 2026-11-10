import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PlusIcon, TagsIcon, Trash2Icon, UserMinusIcon } from 'lucide-react'
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
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ApiError, apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { AttributesDialog, type AttributeTarget } from './attributes-dialog'
import { formatDateTime } from '@/lib/format'

type Group = { id: string; name: string; description: string; createdAt: string }
type GroupDetail = {
  group: Group
  members: Array<{ userId: string; grantedAt: string }>
}
type DirectoryUser = { id: string; name: string; email: string }

const groupsKey = ['admin', 'groups'] as const

function reason(cause: unknown, fallback: string) {
  return cause instanceof ApiError ? cause.message : fallback
}

export function GroupsPage() {
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [openId, setOpenId] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Group | null>(null)
  const [attrTarget, setAttrTarget] = useState<AttributeTarget | null>(null)

  const { data, isPending, error } = useQuery({
    queryKey: groupsKey,
    queryFn: () => apiFetch<{ groups: Group[] }>('/api/admin/directory-groups?limit=100'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/admin/directory-groups/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      setPendingDelete(null)
      toast.success('그룹을 삭제했습니다.')
      await queryClient.invalidateQueries({ queryKey: groupsKey })
    },
    onError: (cause: unknown) => {
      setPendingDelete(null)
      toast.error(reason(cause, '그룹을 삭제하지 못했습니다.'))
    },
  })

  const groups = data?.groups ?? []

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">그룹</h1>
        <Button onClick={() => setCreateOpen(true)}>
          <PlusIcon data-icon="inline-start" />그룹 추가
        </Button>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>그룹 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-12 rounded-md" />
          ))}
        </div>
      ) : groups.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>그룹이 없습니다</EmptyTitle>
            <EmptyDescription>그룹을 만들면 앱 접근 정책에서 사용할 수 있습니다.</EmptyDescription>
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
                <TableHead className="w-32" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {groups.map((group) => (
                <TableRow key={group.id}>
                  <TableCell className="font-medium">{group.name}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">{group.description || '—'}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(group.createdAt)}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    <Button variant="outline" size="sm" onClick={() => setOpenId(group.id)}>
                      멤버
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`${group.name} 속성`}
                      onClick={() => setAttrTarget({ type: 'group', id: group.id, label: group.name })}
                    >
                      <TagsIcon />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`${group.name} 삭제`}
                      onClick={() => setPendingDelete(group)}
                    >
                      <Trash2Icon />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <CreateGroupDialog open={createOpen} onOpenChange={setCreateOpen} />
      <MembersDialog groupId={openId} onClose={() => setOpenId(null)} />
      <AttributesDialog target={attrTarget} onClose={() => setAttrTarget(null)} />

      <AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{pendingDelete?.name} 그룹을 삭제할까요?</AlertDialogTitle>
            <AlertDialogDescription>
              멤버 목록과 그룹 속성이 함께 지워집니다. 이 그룹을 조건으로 쓰는 앱 접근 정책은 그룹이 없어진 상태로 남습니다.
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

function CreateGroupDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: () =>
      apiFetch('/api/admin/directory-groups', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim(), description: description.trim() }),
      }),
    onSuccess: async () => {
      toast.success('그룹을 만들었습니다.')
      setName('')
      setDescription('')
      setFailure(null)
      onOpenChange(false)
      await queryClient.invalidateQueries({ queryKey: groupsKey })
    },
    onError: (cause: unknown) => {
      if (cause instanceof ApiError && cause.status === 409) setFailure('같은 이름의 그룹이 이미 있습니다.')
      else if (cause instanceof ApiError && cause.status === 400) setFailure('이름은 영문, 숫자, 점, 밑줄, 하이픈으로 64자까지 쓸 수 있습니다.')
      else setFailure('그룹을 만들지 못했습니다.')
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
          <DialogTitle>그룹 추가</DialogTitle>
          <DialogDescription>앱 접근 정책과 토큰 클레임에서 쓰는 그룹입니다.</DialogDescription>
        </DialogHeader>
        <form id="create-group" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="group-name">이름</FieldLabel>
              <Input id="group-name" autoComplete="off" spellCheck={false} maxLength={64} value={name} onChange={(event) => setName(event.target.value)} />
              <FieldDescription>영문, 숫자, 점, 밑줄, 하이픈. 예: engineering</FieldDescription>
              {failure ? <FieldError>{failure}</FieldError> : null}
            </Field>
            <Field>
              <FieldLabel htmlFor="group-description">설명</FieldLabel>
              <Input id="group-description" maxLength={512} value={description} onChange={(event) => setDescription(event.target.value)} />
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            취소
          </Button>
          <Button type="submit" form="create-group" disabled={create.isPending || !name.trim()}>
            {create.isPending ? <Spinner data-icon="inline-start" /> : null}
            추가
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function MembersDialog({ groupId, onClose }: { groupId: string | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const key = ['admin', 'group', groupId] as const
  const [term, setTerm] = useState('')
  const [search, setSearch] = useState('')

  const detail = useQuery({
    queryKey: key,
    enabled: groupId !== null,
    queryFn: () => apiFetch<GroupDetail>(`/api/admin/directory-groups/${groupId}`),
  })

  // Members are stored by user id only; the names come from the user list.
  const users = useQuery({
    queryKey: ['admin', 'group-users', search],
    enabled: groupId !== null,
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

  const refresh = () => queryClient.invalidateQueries({ queryKey: key })

  const add = useMutation({
    mutationFn: (userId: string) =>
      apiFetch(`/api/admin/directory-groups/${groupId}/members`, { method: 'POST', body: JSON.stringify({ userId }) }),
    onSuccess: refresh,
    onError: (cause: unknown) => toast.error(reason(cause, '멤버를 추가하지 못했습니다.')),
  })

  const drop = useMutation({
    mutationFn: (userId: string) =>
      apiFetch(`/api/admin/directory-groups/${groupId}/members/${userId}`, { method: 'DELETE' }),
    onSuccess: refresh,
    onError: (cause: unknown) => toast.error(reason(cause, '멤버를 내보내지 못했습니다.')),
  })

  const memberIds = new Set(detail.data?.members.map((member) => member.userId))
  const nameOf = (userId: string) => users.data?.find((user) => user.id === userId)
  const candidates = (users.data ?? []).filter((user) => !memberIds.has(user.id))

  return (
    <Dialog open={groupId !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{detail.data?.group.name ?? '그룹'} 멤버</DialogTitle>
          <DialogDescription>{detail.data?.group.description || '멤버를 추가하거나 내보냅니다.'}</DialogDescription>
        </DialogHeader>

        {detail.error ? (
          <Alert variant="destructive">
            <AlertDescription>그룹 정보를 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : detail.isPending ? (
          <Skeleton className="h-32 rounded-lg" />
        ) : (
          <div className="flex flex-col gap-5">
            <div className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">
                현재 멤버 <Badge variant="secondary">{detail.data.members.length}</Badge>
              </h3>
              {detail.data.members.length === 0 ? (
                <p className="text-sm text-muted-foreground">아직 멤버가 없습니다.</p>
              ) : (
                <ItemGroup className="gap-2">
                  {detail.data.members.map((member) => {
                    const user = nameOf(member.userId)
                    return (
                      <Item key={member.userId} variant="muted" size="sm">
                        <ItemContent>
                          <ItemTitle>{user?.name ?? member.userId}</ItemTitle>
                          <ItemDescription>{user?.email ?? formatDateTime(member.grantedAt)}</ItemDescription>
                        </ItemContent>
                        <ItemActions>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`${user?.email ?? member.userId} 내보내기`}
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
              )}
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
                <ItemGroup className="max-h-48 gap-2 overflow-y-auto">
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
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>닫기</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
