import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRoundIcon, LaptopIcon, MonitorSmartphoneIcon, PlusIcon, SmartphoneIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
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
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { TrustedDevicesSection } from './devices-section'
import { LockdownSection } from './lockdown-section'
import { MfaSection } from './mfa-section'
import { loginConfigQuery } from '@/lib/fingerprint'

type DeviceSession = {
  id: string
  token: string
  createdAt: string
  updatedAt: string | null
  expiresAt: string | null
  current: boolean
  ipAddress: string | null
  userAgent: string | null
  label: string
  location: { city: string | null; region: string | null; country: string | null } | null
}

type PasskeyRow = { id: string; name?: string | null; createdAt?: string | Date | null }

function placeOf(location: DeviceSession['location']): string {
  return location ? [location.city, location.region, location.country].filter(Boolean).join(', ') : ''
}

function SessionsSection() {
  const queryClient = useQueryClient()
  const [target, setTarget] = useState<DeviceSession | null>(null)
  const { data, isPending, error } = useQuery({
    queryKey: ['security', 'sessions'],
    queryFn: async () => (await apiFetch<{ sessions: DeviceSession[] }>('/api/security/sessions/overview')).sessions,
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
    onSettled: () => setTarget(null),
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
            const isCurrent = entry.current
            const location = entry.location
              ? [entry.location.city, entry.location.region, entry.location.country].filter(Boolean).join(', ')
              : ''
            return (
              <Item key={entry.id} variant="outline">
                <ItemMedia variant="icon">
                  {entry.label === '알 수 없는 기기' ? (
                    <MonitorSmartphoneIcon />
                  ) : /iOS|Android/i.test(entry.label) ? (
                    <SmartphoneIcon />
                  ) : (
                    <LaptopIcon />
                  )}
                </ItemMedia>
                <ItemContent>
                  <ItemTitle>
                    {entry.label}
                    {isCurrent ? <Badge variant="secondary">이 기기</Badge> : null}
                  </ItemTitle>
                  <ItemDescription>
                    {location ? <span className="block">{location}</span> : null}
                    {entry.ipAddress ? <span className="block">{entry.ipAddress}</span> : null}
                    {!location && !entry.ipAddress ? <span className="block">IP/위치 정보 없음</span> : null}
                    <span className="block">마지막 활동 {formatDateTime(entry.updatedAt ?? entry.createdAt)}</span>
                  </ItemDescription>
                </ItemContent>
                {!isCurrent ? (
                  <ItemActions>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={revoke.isPending}
                      onClick={() => setTarget(entry)}
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
      <ConfirmDialog
        open={target !== null}
        title="이 기기의 로그인을 종료할까요?"
        description="아래 기기가 맞는지 확인하세요. 종료하면 그 기기는 바로 로그아웃되고 다시 로그인해야 합니다. 이 기기에서 앱에 이미 연결해 둔 로그인 상태는 그대로 남을 수 있으니, 의심스러우면 ‘내 정보’에서 모든 세션을 종료하거나 앱 연결을 해제하세요."
        details={
          target
            ? [
                { label: '기기', value: target.label },
                { label: '위치', value: placeOf(target.location) || '알 수 없음' },
                { label: 'IP', value: target.ipAddress ?? '알 수 없음' },
                { label: '마지막 활동', value: formatDateTime(target.updatedAt ?? target.createdAt) },
              ]
            : []
        }
        confirmLabel="종료"
        pending={revoke.isPending}
        onConfirm={() => target && revoke.mutate(target.token)}
        onCancel={() => setTarget(null)}
      />
    </section>
  )
}

function PasskeysSection() {
  const queryClient = useQueryClient()
  const [target, setTarget] = useState<PasskeyRow | null>(null)
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
    onSettled: () => setTarget(null),
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
                  onClick={() => setTarget(passkey)}
                >
                  <Trash2Icon />
                </Button>
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
      <ConfirmDialog
        open={target !== null}
        title="이 패스키를 삭제할까요?"
        description={
          data && data.length <= 1
            ? '마지막 패스키입니다. 삭제하면 이 기기나 보안 키로는 더 이상 로그인할 수 없습니다. 다른 로그인 방법이 있는지 먼저 확인하세요.'
            : '삭제하면 이 패스키로는 더 이상 로그인할 수 없고, 되돌릴 수 없습니다. 이름과 등록일이 맞는지 확인하세요.'
        }
        details={target ? [{ label: '이름', value: target.name || '패스키' }, { label: '등록일', value: formatDateTime(target.createdAt) }] : []}
        confirmLabel="삭제"
        pending={remove.isPending}
        onConfirm={() => target && remove.mutate(target.id)}
        onCancel={() => setTarget(null)}
      />
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
      <TrustedDevicesSection />
      <LockdownSection />
    </div>
  )
}
