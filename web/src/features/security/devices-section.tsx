import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { LaptopIcon, Trash2Icon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
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
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemMedia, ItemTitle } from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type Device = {
  id: string
  label: string
  created_at: string
  last_seen_at: string
  expires_at: string
  revoked_at: string | null
}

const devicesKey = ['security', 'trusted-devices'] as const

/** Browsers the user chose to trust, with revocation (the server asks for the account password). */
export function TrustedDevicesSection() {
  const { data, isPending, error } = useQuery({
    queryKey: devicesKey,
    queryFn: () => apiFetch<{ devices: Device[] }>('/api/security/trusted-devices'),
  })
  const [target, setTarget] = useState<{ id: string | null; label: string } | null>(null)

  const active = (data?.devices ?? []).filter((device) => !device.revoked_at && new Date(device.expires_at) > new Date())

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-sm font-medium text-muted-foreground">신뢰한 기기</h2>
        {active.length > 1 ? (
          <Button variant="outline" size="sm" onClick={() => setTarget({ id: null, label: '모든 기기' })}>
            모두 해제
          </Button>
        ) : null}
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>신뢰한 기기를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      ) : isPending ? (
        <Skeleton className="h-16 rounded-xl" />
      ) : active.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>신뢰한 기기가 없습니다</EmptyTitle>
            <EmptyDescription>로그인할 때 이 기기를 신뢰하면 한동안 추가 인증을 건너뜁니다.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ItemGroup className="gap-2">
          {active.map((device) => (
            <Item key={device.id} variant="outline">
              <ItemMedia variant="icon">
                <LaptopIcon />
              </ItemMedia>
              <ItemContent>
                <ItemTitle>{device.label || '이름 없는 기기'}</ItemTitle>
                <ItemDescription>
                  마지막 사용 {formatDateTime(device.last_seen_at)} · {formatDateTime(device.expires_at)}까지
                </ItemDescription>
              </ItemContent>
              <ItemActions>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`${device.label || '기기'} 신뢰 해제`}
                  onClick={() => setTarget({ id: device.id, label: device.label || '이 기기' })}
                >
                  <Trash2Icon />
                </Button>
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
      <RevokeDialog target={target} onClose={() => setTarget(null)} />
    </section>
  )
}

function RevokeDialog({
  target,
  onClose,
}: {
  target: { id: string | null; label: string } | null
  onClose: () => void
}) {
  const queryClient = useQueryClient()
  const [password, setPassword] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const revoke = useMutation({
    mutationFn: () =>
      apiFetch(`/api/security/trusted-devices${target?.id ? `/${target.id}` : ''}`, {
        method: 'DELETE',
        body: JSON.stringify({ password }),
      }),
    onSuccess: async () => {
      toast.success('신뢰를 해제했습니다.')
      setPassword('')
      setFailure(null)
      onClose()
      await queryClient.invalidateQueries({ queryKey: devicesKey })
    },
    onError: (cause: unknown) => {
      if (cause instanceof ApiError && cause.status === 409) {
        setFailure('이 계정은 비밀번호 확인을 쓸 수 없습니다. 관리자에게 신뢰한 기기 해제를 요청하세요.')
      } else if (cause instanceof ApiError && (cause.status === 400 || cause.status === 401 || cause.status === 403)) {
        setFailure('비밀번호가 올바르지 않습니다.')
      } else {
        setFailure('해제하지 못했습니다.')
      }
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    revoke.mutate()
  }

  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && !revoke.isPending && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{target?.label} 신뢰 해제</DialogTitle>
          <DialogDescription>해제하면 다음 로그인부터 이 기기에서도 추가 인증을 합니다. 계정 비밀번호로 확인합니다.</DialogDescription>
        </DialogHeader>
        <form id="revoke-device" onSubmit={submit} noValidate>
          <FieldGroup>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="revoke-password">계정 비밀번호</FieldLabel>
              <Input
                id="revoke-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              {failure ? <FieldError>{failure}</FieldError> : null}
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={revoke.isPending}>
            취소
          </Button>
          <Button type="submit" form="revoke-device" disabled={revoke.isPending || !password}>
            {revoke.isPending ? <Spinner data-icon="inline-start" /> : null}
            해제
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
