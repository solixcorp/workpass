import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { LockKeyholeIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Item, ItemActions, ItemContent, ItemDescription, ItemMedia, ItemTitle } from '@/components/ui/item'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'

/** Emergency self-lockdown: ends every session and blocks sign-in until an administrator unlocks the account. */
export function LockdownSection() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const lock = useMutation({
    mutationFn: () => apiFetch('/api/security/account-lockdown', { method: 'POST', body: JSON.stringify({ reason: reason.trim() }) }),
    onSuccess: async () => {
      queryClient.clear()
      await navigate({ to: '/login', replace: true })
    },
    onError: (cause: unknown) => {
      if (cause instanceof ApiError && cause.status === 409) setFailure('이미 잠긴 계정입니다.')
      else if (cause instanceof ApiError && cause.status === 400) setFailure('사유를 1자에서 500자 사이로 입력하세요.')
      else setFailure('잠그지 못했습니다.')
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    lock.mutate()
  }

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium text-muted-foreground">비상 조치</h2>
      <Item variant="outline">
        <ItemMedia variant="icon">
          <LockKeyholeIcon />
        </ItemMedia>
        <ItemContent>
          <ItemTitle>내 계정 잠그기</ItemTitle>
          <ItemDescription>
            계정이 도용된 것 같을 때 쓰세요. 모든 기기에서 로그아웃되고, 관리자가 풀어 줄 때까지 로그인할 수 없습니다.
          </ItemDescription>
        </ItemContent>
        <ItemActions>
          <Button variant="destructive" size="sm" onClick={() => setOpen(true)}>
            잠그기
          </Button>
        </ItemActions>
      </Item>

      <Dialog open={open} onOpenChange={(next) => !lock.isPending && setOpen(next)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>계정을 잠글까요?</DialogTitle>
            <DialogDescription>
              바로 모든 세션이 끝나고 이 계정으로 로그인할 수 없게 됩니다. 풀려면 관리자에게 요청해야 합니다.
            </DialogDescription>
          </DialogHeader>
          <form id="lockdown" onSubmit={submit} noValidate>
            <FieldGroup>
              <Field data-invalid={failure ? true : undefined}>
                <FieldLabel htmlFor="lockdown-reason">사유</FieldLabel>
                <Textarea id="lockdown-reason" rows={3} maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} />
                <FieldDescription>관리자가 확인할 수 있게 남깁니다.</FieldDescription>
                {failure ? <FieldError>{failure}</FieldError> : null}
              </Field>
            </FieldGroup>
          </form>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)} disabled={lock.isPending}>
              취소
            </Button>
            <Button type="submit" form="lockdown" variant="destructive" disabled={lock.isPending || !reason.trim()}>
              {lock.isPending ? <Spinner data-icon="inline-start" /> : null}
              계정 잠그기
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}
