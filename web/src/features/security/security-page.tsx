import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRoundIcon, MonitorSmartphoneIcon, PlusIcon, Trash2Icon } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { authClient } from '@/lib/auth-client'
import { formatDateTime } from '@/lib/format'
import { sessionQuery } from '@/lib/queries'
import { MfaSection } from './mfa-section'
import { loginConfigQuery } from '@/lib/fingerprint'

type DeviceSession = {
  id: string
  token: string
  userAgent?: string | null
  ipAddress?: string | null
  createdAt: string | Date
}

type PasskeyRow = { id: string; name?: string | null; createdAt?: string | Date | null }

function describeAgent(userAgent: string | null | undefined): string {
  if (!userAgent) return '알 수 없는 기기'
  const browser = /Edg\//.test(userAgent)
    ? 'Edge'
    : /Chrome\//.test(userAgent)
      ? 'Chrome'
      : /Firefox\//.test(userAgent)
        ? 'Firefox'
        : /Safari\//.test(userAgent)
          ? 'Safari'
          : '브라우저'
  const system = /Windows/.test(userAgent)
    ? 'Windows'
    : /Mac OS X/.test(userAgent)
      ? 'macOS'
      : /Android/.test(userAgent)
        ? 'Android'
        : /iPhone|iPad/.test(userAgent)
          ? 'iOS'
          : /Linux/.test(userAgent)
            ? 'Linux'
            : ''
  return system ? `${browser} · ${system}` : browser
}

function SessionsSection() {
  const queryClient = useQueryClient()
  const { data: current } = useQuery(sessionQuery)
  const { data, isPending, error } = useQuery({
    queryKey: ['security', 'sessions'],
    queryFn: async () => {
      const result = await authClient.listSessions()
      if (result.error) throw new Error(result.error.message ?? 'Failed to load sessions')
      return result.data as DeviceSession[]
    },
  })

  const revoke = useMutation({
    mutationFn: async (token: string) => {
      const result = await authClient.revokeSession({ token })
      if (result.error) throw new Error(result.error.message ?? 'Failed to revoke')
    },
    onSuccess: () => {
      toast.success('세션을 종료했습니다.')
      return queryClient.invalidateQueries({ queryKey: ['security', 'sessions'] })
    },
    onError: () => toast.error('세션을 종료하지 못했습니다.'),
  })

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium text-muted-foreground">로그인된 기기</h2>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>세션 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-16 rounded-lg" />
      ) : (
        <ItemGroup className="gap-2">
          {data.map((entry) => {
            const isCurrent = entry.token === current?.session.token
            return (
              <Item key={entry.id} variant="outline">
                <ItemMedia variant="icon">
                  <MonitorSmartphoneIcon />
                </ItemMedia>
                <ItemContent>
                  <ItemTitle>
                    {describeAgent(entry.userAgent)}
                    {isCurrent ? <Badge variant="secondary">이 기기</Badge> : null}
                  </ItemTitle>
                  <ItemDescription>
                    {entry.ipAddress ? `${entry.ipAddress} · ` : ''}
                    {formatDateTime(entry.createdAt)}
                  </ItemDescription>
                </ItemContent>
                {!isCurrent ? (
                  <ItemActions>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={revoke.isPending}
                      onClick={() => revoke.mutate(entry.token)}
                    >
                      종료
                    </Button>
                  </ItemActions>
                ) : null}
              </Item>
            )
          })}
        </ItemGroup>
      )}
    </section>
  )
}

function PasskeysSection() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useQuery({
    queryKey: ['security', 'passkeys'],
    queryFn: async () => {
      const result = await authClient.passkey.listUserPasskeys()
      if (result.error) throw new Error(result.error.message ?? 'Failed to load passkeys')
      return result.data as PasskeyRow[]
    },
  })

  const add = useMutation({
    mutationFn: async () => {
      const result = await authClient.passkey.addPasskey({ name: '내 패스키' })
      if (result?.error) throw new Error(result.error.message ?? 'Failed to add passkey')
    },
    onSuccess: () => {
      toast.success('패스키를 등록했습니다.')
      return queryClient.invalidateQueries({ queryKey: ['security', 'passkeys'] })
    },
    onError: () => toast.error('패스키를 등록하지 못했습니다.'),
  })

  const remove = useMutation({
    mutationFn: async (id: string) => {
      const result = await authClient.passkey.deletePasskey({ id })
      if (result.error) throw new Error(result.error.message ?? 'Failed to delete passkey')
    },
    onSuccess: () => {
      toast.success('패스키를 삭제했습니다.')
      return queryClient.invalidateQueries({ queryKey: ['security', 'passkeys'] })
    },
    onError: () => toast.error('패스키를 삭제하지 못했습니다.'),
  })

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-sm font-medium text-muted-foreground">패스키</h2>
        <Button variant="outline" size="sm" disabled={add.isPending} onClick={() => add.mutate()}>
          {add.isPending ? <Spinner data-icon="inline-start" /> : <PlusIcon data-icon="inline-start" />}
          패스키 추가
        </Button>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>패스키 목록을 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-16 rounded-lg" />
      ) : data.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>등록된 패스키가 없습니다</EmptyTitle>
            <EmptyDescription>패스키를 등록하면 비밀번호 없이 로그인할 수 있습니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ItemGroup className="gap-2">
          {data.map((passkey) => (
            <Item key={passkey.id} variant="outline">
              <ItemMedia variant="icon">
                <KeyRoundIcon />
              </ItemMedia>
              <ItemContent>
                <ItemTitle>{passkey.name || '패스키'}</ItemTitle>
                <ItemDescription>{formatDateTime(passkey.createdAt)}</ItemDescription>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="패스키 삭제"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(passkey.id)}
                >
                  <Trash2Icon />
                </Button>
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
    </section>
  )
}

/** Passkeys appear only while the server's login policy allows them. */
function PasskeysGate() {
  const { data } = useQuery(loginConfigQuery)
  return data?.login.passkey ? <PasskeysSection /> : null
}

export function SecurityPage() {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-8">
      <h1 className="text-2xl font-semibold">보안</h1>
      <MfaSection />
      <PasskeysGate />
      <SessionsSection />
    </div>
  )
}
