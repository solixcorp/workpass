import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CopyIcon, MailIcon, PlusIcon, ShieldIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
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
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Spinner } from '@/components/ui/spinner'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { UserActions } from './user-actions'
import { UserMfaDialog, type MfaUser } from './user-mfa-dialog'
import { apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { sessionQuery } from '@/lib/queries'
import { formatDateTime } from '@/lib/format'

const PAGE_SIZE = 25

type AdminUser = {
  id: string
  name: string
  email: string
  role?: string | null
  banned?: boolean | null
  createdAt: string | Date
}

type ActivationOutcome = {
  expiresAt: string
  emailed: boolean
  activationUrl: string | null
  emailError: boolean
}

type LinkDialogState = { email: string; outcome: ActivationOutcome } | null

export function UsersPage() {
  const queryClient = useQueryClient()
  const { data: session } = useQuery(sessionQuery)
  const [createOpen, setCreateOpen] = useState(false)
  const [mfaUser, setMfaUser] = useState<MfaUser | null>(null)
  const [linkDialog, setLinkDialog] = useState<LinkDialogState>(null)
  const [term, setTerm] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)

  const { data, isPending, error } = useQuery({
    queryKey: ['admin', 'users', search, page],
    queryFn: async () => {
      const result = await authClient.admin.listUsers({
        query: {
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
          sortBy: 'createdAt',
          sortDirection: 'desc',
          ...(search
            ? { searchField: 'email' as const, searchOperator: 'contains' as const, searchValue: search }
            : {}),
        },
      })
      if (result.error) throw new Error(result.error.message ?? 'Failed to load users')
      return result.data as { users: AdminUser[]; total: number }
    },
  })

  const sendLink = useMutation({
    mutationFn: async (user: AdminUser) => {
      const result = await apiFetch<{ activation: ActivationOutcome }>(
        `/api/admin/users/${user.id}/activation-link`,
        { method: 'POST', body: JSON.stringify({}) },
      )
      return { email: user.email, outcome: result.activation }
    },
    onSuccess: (state) => setLinkDialog(state),
    onError: () => toast.error('링크를 만들지 못했습니다.'),
  })

  const users = data?.users ?? []
  const total = data?.total ?? 0
  const lastPage = Math.max(0, Math.ceil(total / PAGE_SIZE) - 1)

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">사용자</h1>
        <Button onClick={() => setCreateOpen(true)}>
          <PlusIcon data-icon="inline-start" />사용자 추가
        </Button>
      </div>

      <form
        className="flex max-w-md gap-2"
        onSubmit={(event) => {
          event.preventDefault()
          setPage(0)
          setSearch(term.trim())
        }}
      >
        <Input
          aria-label="이메일 검색"
          placeholder="이메일로 검색"
          value={term}
          onChange={(event) => setTerm(event.target.value)}
        />
        <Button type="submit">검색</Button>
      </form>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>사용자 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 6 }, (_, index) => (
            <Skeleton key={index} className="h-12 rounded-md" />
          ))}
        </div>
      ) : users.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>사용자가 없습니다</EmptyTitle>
            <EmptyDescription>검색어를 바꿔 보세요.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>사용자</TableHead>
                  <TableHead>역할</TableHead>
                  <TableHead>상태</TableHead>
                  <TableHead>가입일</TableHead>
                  <TableHead className="w-32" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <Avatar size="sm">
                          <AvatarFallback>
                            {(user.name || user.email).slice(0, 2).toUpperCase()}
                          </AvatarFallback>
                        </Avatar>
                        <div className="flex min-w-0 flex-col">
                          <span className="truncate font-medium">{user.name}</span>
                          <span className="truncate text-xs text-muted-foreground">{user.email}</span>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {user.role?.split(',').includes('admin') ? (
                        <Badge>관리자</Badge>
                      ) : (
                        <Badge variant="outline">사용자</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {user.banned ? (
                        <Badge variant="destructive">비활성</Badge>
                      ) : (
                        <Badge variant="secondary">활성</Badge>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">
                      {formatDateTime(user.createdAt)}
                    </TableCell>
                    <TableCell className="whitespace-nowrap">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`${user.email} 2차 인증 관리`}
                        onClick={() => setMfaUser({ id: user.id, name: user.name, email: user.email })}
                      >
                        <ShieldIcon />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`${user.email} 비밀번호 설정 링크 보내기`}
                        disabled={sendLink.isPending}
                        onClick={() => sendLink.mutate(user)}
                      >
                        <MailIcon />
                      </Button>
                      <UserActions user={user} currentUserId={session?.user.id} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              총 {total.toLocaleString('ko-KR')}명 · {page + 1} / {lastPage + 1}
            </span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
                이전
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= lastPage}
                onClick={() => setPage(page + 1)}
              >
                다음
              </Button>
            </div>
          </div>
        </>
      )}
      <UserMfaDialog user={mfaUser} onClose={() => setMfaUser(null)} />
      <CreateUserDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(state) => {
          setLinkDialog(state)
          void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
        }}
      />
      <LinkDialog state={linkDialog} onClose={() => setLinkDialog(null)} />
    </div>
  )
}

function CreateUserDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (state: NonNullable<LinkDialogState>) => void
}) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: () =>
      apiFetch<{ user: { email: string }; activation: ActivationOutcome }>('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({ name, email }),
      }),
    onSuccess: (result) => {
      setName('')
      setEmail('')
      setError(null)
      onOpenChange(false)
      onCreated({ email: result.user.email, outcome: result.activation })
    },
    onError: (failure: Error) => setError(failure.message),
  })

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    create.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} noValidate className="flex flex-col gap-6">
          <DialogHeader>
            <DialogTitle>사용자 추가</DialogTitle>
            <DialogDescription>
              계정을 만들고 비밀번호를 설정할 수 있는 링크를 보냅니다.
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            <Field>
              <FieldLabel htmlFor="new-user-name">이름</FieldLabel>
              <Input id="new-user-name" required value={name} onChange={(event) => setName(event.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="new-user-email">이메일</FieldLabel>
              <Input
                id="new-user-email"
                type="email"
                required
                autoCapitalize="off"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              취소
            </Button>
            <Button type="submit" disabled={create.isPending || !name.trim() || !email.trim()}>
              {create.isPending ? <Spinner data-icon="inline-start" /> : null}
              추가
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function LinkDialog({ state, onClose }: { state: LinkDialogState; onClose: () => void }) {
  const outcome = state?.outcome
  return (
    <Dialog open={state !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>비밀번호 설정 링크</DialogTitle>
          <DialogDescription>
            {outcome?.emailed
              ? `${state?.email}으로 링크를 보냈습니다.`
              : '메일을 보내지 못해 링크를 직접 전달해야 합니다. 이 링크는 지금 한 번만 볼 수 있습니다.'}
          </DialogDescription>
        </DialogHeader>
        {outcome?.activationUrl ? (
          <div className="flex flex-col gap-3">
            {outcome.emailError ? (
              <Alert variant="destructive">
                <AlertDescription>메일 발송에 실패했습니다.</AlertDescription>
              </Alert>
            ) : null}
            <div className="flex gap-2">
              <Input readOnly aria-label="비밀번호 설정 링크" value={outcome.activationUrl} />
              <Button
                variant="outline"
                size="icon"
                aria-label="링크 복사"
                onClick={async () => {
                  await navigator.clipboard.writeText(outcome.activationUrl!)
                  toast.success('링크를 복사했습니다.')
                }}
              >
                <CopyIcon />
              </Button>
            </div>
          </div>
        ) : null}
        {outcome ? (
          <p className="text-sm text-muted-foreground">
            {formatDateTime(outcome.expiresAt)}까지 한 번 사용할 수 있습니다.
          </p>
        ) : null}
        <DialogFooter>
          <Button onClick={onClose}>확인</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
