import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRoundIcon, LogOutIcon, MoreHorizontalIcon, ShieldCheckIcon, UserCheckIcon, UserXIcon } from 'lucide-react'
import { useState } from 'react'
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
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { sessionQuery } from '@/lib/queries'

export type ManagedUser = {
  id: string
  name: string
  email: string
  role?: string | null
  banned?: boolean | null
}

type Action = 'ban' | 'unban' | 'grant-admin' | 'revoke-admin' | 'sessions' | 'unlock'

type Lockdown = { id: string; reason: string; createdAt: string; liftedAt: string | null }

const COPY: Record<Action, { title: (u: ManagedUser) => string; body: string; confirm: string; done: string; destructive?: boolean }> = {
  ban: {
    title: (u) => `${u.email}을(를) 비활성화할까요?`,
    body: '이 사용자는 더 이상 로그인할 수 없고, 열려 있는 세션과 신뢰한 기기가 모두 끝납니다. 데이터는 지워지지 않으며 언제든 다시 활성화할 수 있습니다.',
    confirm: '비활성화',
    done: '사용자를 비활성화했습니다.',
    destructive: true,
  },
  unban: {
    title: (u) => `${u.email}을(를) 다시 활성화할까요?`,
    body: '다시 로그인할 수 있게 됩니다.',
    confirm: '활성화',
    done: '사용자를 활성화했습니다.',
  },
  'grant-admin': {
    title: (u) => `${u.email}에게 관리자 권한을 줄까요?`,
    body: '사용자, 앱, 설정, 감사 로그를 포함한 관리 콘솔 전체에 접근할 수 있게 됩니다.',
    confirm: '관리자로 지정',
    done: '관리자로 지정했습니다.',
  },
  'revoke-admin': {
    title: (u) => `${u.email}의 관리자 권한을 해제할까요?`,
    body: '일반 사용자로 바뀌어 관리 콘솔에 접근할 수 없게 됩니다.',
    confirm: '권한 해제',
    done: '관리자 권한을 해제했습니다.',
    destructive: true,
  },
  unlock: {
    title: (u) => `${u.email}의 잠금을 풀까요?`,
    body: '사용자가 직접 잠근 계정이거나 비상 조치로 잠긴 계정입니다. 풀어도 비밀번호 등록이 지워진 상태라서, 풀고 나면 새 비밀번호를 정하는 링크를 바로 보냅니다. 세션과 신뢰한 기기는 이미 끝난 상태 그대로입니다.',
    confirm: '잠금 해제',
    done: '잠금을 풀었습니다. 이어서 비밀번호 설정 링크를 보냅니다.',
  },
  sessions: {
    title: (u) => `${u.email}의 모든 세션을 끝낼까요?`,
    body: '이 사용자가 로그인해 둔 모든 기기에서 로그아웃됩니다. 계정 자체는 그대로입니다.',
    confirm: '세션 종료',
    done: '모든 세션을 종료했습니다.',
    destructive: true,
  },
}

/** Row menu for one user: deactivate, role and session controls. */
export function UserActions({
  user,
  currentUserId,
  onUnlocked,
}: {
  user: ManagedUser
  currentUserId: string | undefined
  /** Called after a lockdown is lifted so the page can offer the password-setup link. */
  onUnlocked?: (user: ManagedUser) => void
}) {
  const queryClient = useQueryClient()
  const [action, setAction] = useState<Action | null>(null)
  const lockdowns = useQuery({
    queryKey: ['admin', 'lockdown', user.id],
    queryFn: () => apiFetch<{ lockdowns: Lockdown[] }>(`/api/security/account-lockdown/user/${user.id}`),
    enabled: Boolean(user.banned),
    staleTime: 10_000,
  })
  const locked = Boolean(user.banned) && Boolean(lockdowns.data?.lockdowns.some((entry) => !entry.liftedAt))
  const isAdmin = Boolean(user.role?.split(',').includes('admin'))
  const isSelf = user.id === currentUserId

  const run = useMutation({
    mutationFn: async (kind: Action) => {
      if (kind === 'unlock') {
        await apiFetch(`/api/security/account-lockdown/user/${user.id}/unlock`, { method: 'POST', body: '{}' })
        return
      }
      const result =
        kind === 'ban'
          ? await authClient.admin.banUser({ userId: user.id })
          : kind === 'unban'
            ? await authClient.admin.unbanUser({ userId: user.id })
            : kind === 'sessions'
              ? await authClient.admin.revokeUserSessions({ userId: user.id })
              : await authClient.admin.setRole({ userId: user.id, role: kind === 'grant-admin' ? 'admin' : 'user' })
      if (result.error) throw new Error(result.error.message ?? 'failed')
    },
    onSuccess: async (_, kind) => {
      toast.success(COPY[kind].done)
      setAction(null)
      if (kind === 'unlock') onUnlocked?.(user)
      await queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
      if (isSelf) await queryClient.invalidateQueries({ queryKey: sessionQuery.queryKey })
    },
    onError: () => {
      toast.error('처리하지 못했습니다.')
      setAction(null)
    },
  })

  const copy = action ? COPY[action] : null

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`${user.email} 더 보기`}>
            <MoreHorizontalIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          {isAdmin ? (
            <DropdownMenuItem disabled={isSelf} onSelect={() => setAction('revoke-admin')}>
              <ShieldCheckIcon />
              관리자 권한 해제
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem onSelect={() => setAction('grant-admin')}>
              <ShieldCheckIcon />
              관리자로 지정
            </DropdownMenuItem>
          )}
          <DropdownMenuItem disabled={isSelf} onSelect={() => setAction('sessions')}>
            <LogOutIcon />
            모든 세션 종료
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          {locked ? (
            <DropdownMenuItem onSelect={() => setAction('unlock')}>
              <KeyRoundIcon />
              잠금 해제
            </DropdownMenuItem>
          ) : user.banned ? (
            <DropdownMenuItem onSelect={() => setAction('unban')}>
              <UserCheckIcon />
              다시 활성화
            </DropdownMenuItem>
          ) : (
            <DropdownMenuItem variant="destructive" disabled={isSelf} onSelect={() => setAction('ban')}>
              <UserXIcon />
              비활성화
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      <AlertDialog open={action !== null} onOpenChange={(open) => !open && !run.isPending && setAction(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{copy?.title(user)}</AlertDialogTitle>
            <AlertDialogDescription>{copy?.body}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={run.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction
              variant={copy?.destructive ? 'destructive' : 'default'}
              disabled={run.isPending}
              onClick={(event) => {
                event.preventDefault()
                if (action) run.mutate(action)
              }}
            >
              {copy?.confirm}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
