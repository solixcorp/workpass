import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRoundIcon, LaptopIcon, MonitorSmartphoneIcon, PencilIcon, PlusIcon, SmartphoneIcon, Trash2Icon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
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
  trust: { level: 'trusted' | 'normal' | 'review' | 'risky' | 'unknown'; score: number; observedAt: string | null }
}

const TRUST_COPY: Record<DeviceSession['trust']['level'], { label: string; note: string; className: string }> = {
  trusted: { label: '안전', note: '로그인할 때 위험 신호가 없었습니다.', className: 'text-green-700 dark:text-green-400' },
  normal: { label: '대체로 안전', note: '사소한 신호가 있었지만 로그인을 막을 정도는 아니었습니다.', className: 'text-green-700 dark:text-green-400' },
  review: { label: '확인 필요', note: '로그인할 때 추가 확인이 필요한 신호가 있었습니다.', className: 'text-amber-700 dark:text-amber-400' },
  risky: { label: '위험', note: '로그인할 때 위험 신호가 감지되었습니다. 본인이 아니라면 종료하세요.', className: 'text-destructive' },
  unknown: { label: '평가 없음', note: '이 기기는 아직 위험 평가 기록이 없습니다.', className: 'text-muted-foreground' },
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
                    <span className={`block ${TRUST_COPY[entry.trust.level].className}`} title={TRUST_COPY[entry.trust.level].note}>
                      {entry.trust.level === 'unknown'
                        ? TRUST_COPY.unknown.note
                        : `이 기기는 ${TRUST_COPY[entry.trust.level].label}으로 판단했습니다 (점수 ${entry.trust.score}/100)`}
                    </span>
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

const DEFAULT_PASSKEY_NAME = '내 패스키'

/** Names a new passkey before the browser prompt, or renames an existing one. */
function PasskeyNameDialog({
  open,
  initialName,
  title,
  description,
  confirmLabel,
  pending,
  onConfirm,
  onCancel,
}: {
  open: boolean
  initialName: string
  title: string
  description: string
  confirmLabel: string
  pending: boolean
  onConfirm: (name: string) => void
  onCancel: () => void
}) {
  const [name, setName] = useState(initialName)
  const trimmed = name.trim()

  function submit(event: FormEvent) {
    event.preventDefault()
    if (trimmed && !pending) onConfirm(trimmed)
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !pending && onCancel()}>
      <DialogContent className="sm:max-w-sm">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="passkey-name">패스키 이름</FieldLabel>
              <Input
                id="passkey-name"
                autoFocus
                maxLength={64}
                value={name}
                onChange={(event) => setName(event.target.value)}
                onFocus={(event) => event.target.select()}
              />
              <FieldDescription>예: 회사 맥북, 개인 휴대폰, 보안 키</FieldDescription>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={pending} onClick={onCancel}>
              취소
            </Button>
            <Button type="submit" disabled={pending || !trimmed}>
              {pending ? <Spinner data-icon="inline-start" /> : null}
              {confirmLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function PasskeysSection() {
  const queryClient = useQueryClient()
  const [target, setTarget] = useState<PasskeyRow | null>(null)
  const [renaming, setRenaming] = useState<PasskeyRow | null>(null)
  const [adding, setAdding] = useState(false)
  const { data, isPending, error } = useQuery({
    queryKey: ['security', 'passkeys'],
    queryFn: async () => {
      const result = await authClient.passkey.listUserPasskeys()
      if (result.error) throw new Error(result.error.message ?? 'Failed to load passkeys')
      return result.data as PasskeyRow[]
    },
  })

  const add = useMutation({
    mutationFn: async (name: string) => {
      const result = await authClient.passkey.addPasskey({ name })
      if (result?.error) throw new Error(result.error.message ?? 'Failed to add passkey')
    },
    onSuccess: () => {
      toast.success('패스키를 등록했습니다.')
      return queryClient.invalidateQueries({ queryKey: ['security', 'passkeys'] })
    },
    onError: () => toast.error('패스키를 등록하지 못했습니다.'),
    onSettled: () => setAdding(false),
  })

  const rename = useMutation({
    mutationFn: async ({ id, name }: { id: string; name: string }) => {
      const result = await authClient.passkey.updatePasskey({ id, name })
      if (result.error) throw new Error(result.error.message ?? 'Failed to rename passkey')
    },
    onSuccess: () => {
      toast.success('패스키 이름을 바꿨습니다.')
      return queryClient.invalidateQueries({ queryKey: ['security', 'passkeys'] })
    },
    onError: () => toast.error('패스키 이름을 바꾸지 못했습니다.'),
    onSettled: () => setRenaming(null),
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
        <Button variant="outline" size="sm" disabled={add.isPending} onClick={() => setAdding(true)}>
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
                  aria-label="패스키 이름 변경"
                  disabled={rename.isPending}
                  onClick={() => setRenaming(passkey)}
                >
                  <PencilIcon />
                </Button>
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
      <PasskeyNameDialog
        key={adding ? 'add-open' : 'add-closed'}
        open={adding}
        initialName={DEFAULT_PASSKEY_NAME}
        title="패스키 추가"
        description="나중에 구분할 수 있게 이름을 정하세요. 다음 단계에서 브라우저가 패스키 만들기를 안내합니다."
        confirmLabel="계속"
        pending={add.isPending}
        onConfirm={(name) => add.mutate(name)}
        onCancel={() => setAdding(false)}
      />
      <PasskeyNameDialog
        key={renaming?.id ?? 'rename-closed'}
        open={renaming !== null}
        initialName={renaming?.name || DEFAULT_PASSKEY_NAME}
        title="패스키 이름 변경"
        description="이름만 바뀌고 로그인 방법은 그대로입니다."
        confirmLabel="저장"
        pending={rename.isPending}
        onConfirm={(name) => renaming && rename.mutate({ id: renaming.id, name })}
        onCancel={() => setRenaming(null)}
      />
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
