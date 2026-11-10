import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Trash2Icon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemTitle,
} from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

type UserMfa = {
  required: boolean
  enrolled: boolean
  twoFactorEnabled: boolean
  authenticatorApp: boolean
  hotpTokens: Array<{ id: string; label: string; createdAt: string }>
  allowed: { totp: boolean; otp: boolean; hotp: boolean; duo: boolean }
}

export type MfaUser = { id: string; name: string; email: string }

/** What a user has set up, plus the administrator's recovery actions. */
export function UserMfaDialog({ user, onClose }: { user: MfaUser | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const key = ['admin', 'user-mfa', user?.id] as const
  const { data, isPending, error } = useQuery({
    queryKey: key,
    enabled: user !== null,
    queryFn: () => apiFetch<UserMfa>(`/api/admin/users/${user!.id}/mfa`),
  })
  const [label, setLabel] = useState('')
  const [seed, setSeed] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  const [confirmReset, setConfirmReset] = useState(false)

  const refresh = () => queryClient.invalidateQueries({ queryKey: key })
  const fail = (cause: unknown) => setFailure(cause instanceof ApiError ? cause.message : '처리하지 못했습니다.')

  const attach = useMutation({
    mutationFn: () =>
      apiFetch(`/api/admin/users/${user!.id}/mfa/hotp`, {
        method: 'POST',
        body: JSON.stringify({ label: label.trim(), secretBase32: seed }),
      }),
    onSuccess: async () => {
      setFailure(null)
      setLabel('')
      setSeed('')
      toast.success('토큰을 추가했습니다.')
      await refresh()
    },
    onError: fail,
  })

  const remove = useMutation({
    mutationFn: (tokenId: string) =>
      apiFetch(`/api/admin/users/${user!.id}/mfa/hotp/${tokenId}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('토큰을 삭제했습니다.')
      await refresh()
    },
    onError: fail,
  })

  const reset = useMutation({
    mutationFn: () => apiFetch(`/api/admin/users/${user!.id}/mfa/reset`, { method: 'POST', body: '{}' }),
    onSuccess: async () => {
      setConfirmReset(false)
      toast.success('2차 인증을 초기화했습니다. 사용자는 다시 등록해야 합니다.')
      await refresh()
    },
    onError: (cause: unknown) => {
      setConfirmReset(false)
      fail(cause)
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    attach.mutate()
  }

  return (
    <>
      <Dialog open={user !== null} onOpenChange={(open) => !open && onClose()}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>2차 인증 관리</DialogTitle>
            <DialogDescription>{user?.email}</DialogDescription>
          </DialogHeader>

          {error ? (
            <Alert variant="destructive">
              <AlertDescription>정보를 불러오지 못했습니다.</AlertDescription>
            </Alert>
          ) : isPending || !data ? (
            <Skeleton className="h-40 rounded-lg" />
          ) : (
            <div className="flex flex-col gap-5">
              <ItemGroup className="gap-2">
                <Item variant="outline" size="sm">
                  <ItemContent>
                    <ItemTitle>상태</ItemTitle>
                    <ItemDescription>
                      {data.required ? '이 계정은 2차 인증이 필수입니다.' : '필수 대상이 아닙니다.'}
                    </ItemDescription>
                  </ItemContent>
                  <ItemActions>
                    <Badge variant={data.enrolled ? 'secondary' : 'outline'}>
                      {data.enrolled ? '등록됨' : '등록 안 됨'}
                    </Badge>
                  </ItemActions>
                </Item>
                <Item variant="outline" size="sm">
                  <ItemContent>
                    <ItemTitle>인증 앱 · 일회용 코드</ItemTitle>
                    <ItemDescription>
                      {data.authenticatorApp ? '인증 앱이 등록돼 있습니다.' : data.twoFactorEnabled ? '일회용 코드만 켜져 있습니다.' : '켜져 있지 않습니다.'}
                    </ItemDescription>
                  </ItemContent>
                </Item>
              </ItemGroup>

              <div className="flex flex-col gap-2">
                <h3 className="text-sm font-medium">보안 토큰</h3>
                {data.hotpTokens.length === 0 ? (
                  <p className="text-sm text-muted-foreground">등록된 토큰이 없습니다.</p>
                ) : (
                  <ItemGroup className="gap-2">
                    {data.hotpTokens.map((token) => (
                      <Item key={token.id} variant="muted" size="sm">
                        <ItemContent>
                          <ItemTitle>{token.label}</ItemTitle>
                          <ItemDescription>{formatDateTime(token.createdAt)}</ItemDescription>
                        </ItemContent>
                        <ItemActions>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`${token.label} 삭제`}
                            disabled={remove.isPending}
                            onClick={() => remove.mutate(token.id)}
                          >
                            <Trash2Icon />
                          </Button>
                        </ItemActions>
                      </Item>
                    ))}
                  </ItemGroup>
                )}
                {data.allowed.hotp ? (
                  <form onSubmit={submit} noValidate>
                    <FieldGroup>
                      <Field>
                        <FieldLabel htmlFor="admin-hotp-label">토큰 이름</FieldLabel>
                        <Input id="admin-hotp-label" maxLength={64} value={label} onChange={(event) => setLabel(event.target.value)} />
                      </Field>
                      <Field data-invalid={failure ? true : undefined}>
                        <FieldLabel htmlFor="admin-hotp-seed">토큰 키 (Base32)</FieldLabel>
                        <Input
                          id="admin-hotp-seed"
                          autoComplete="off"
                          spellCheck={false}
                          className="font-mono"
                          value={seed}
                          onChange={(event) => setSeed(event.target.value)}
                        />
                        <FieldDescription>제조사에서 받은 키입니다. 저장한 뒤에는 볼 수 없습니다.</FieldDescription>
                        {failure ? <FieldError>{failure}</FieldError> : null}
                      </Field>
                      <Field>
                        <div>
                          <Button type="submit" variant="outline" size="sm" disabled={attach.isPending || !label.trim() || !seed.trim()}>
                            {attach.isPending ? <Spinner data-icon="inline-start" /> : null}
                            토큰 추가
                          </Button>
                        </div>
                      </Field>
                    </FieldGroup>
                  </form>
                ) : (
                  <p className="text-sm text-muted-foreground">설정에서 보안 토큰이 꺼져 있어 추가할 수 없습니다.</p>
                )}
              </div>
            </div>
          )}

          <DialogFooter className="sm:justify-between">
            <Button variant="destructive" disabled={!data || reset.isPending} onClick={() => setConfirmReset(true)}>
              2차 인증 초기화
            </Button>
            <Button variant="outline" onClick={onClose}>
              닫기
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={confirmReset} onOpenChange={setConfirmReset}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{user?.email}의 2차 인증을 초기화할까요?</AlertDialogTitle>
            <AlertDialogDescription>
              인증 앱, 일회용 코드, 백업 코드, 보안 토큰이 모두 지워지고 열려 있는 인증 기록도 사라집니다. 사용자가 휴대폰을 잃어버렸을 때 쓰세요. 필수 대상이면 다음 로그인 때 다시 등록해야 합니다.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>취소</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => reset.mutate()}>
              초기화
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
