import { useMutation } from '@tanstack/react-query'
import { CopyIcon, Share2Icon } from 'lucide-react'
import { useId, useState } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldContent, FieldDescription, FieldLabel, FieldLegend, FieldSet } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Spinner } from '@/components/ui/spinner'
import { apiFetch } from '@/lib/api'
import { formatDateTime } from '@/lib/format'

export type ActivationOutcome = {
  expiresAt: string
  emailed: boolean
  activationUrl: string | null
  emailError: boolean
}

export type ActivationLinkState = { email: string; outcome: ActivationOutcome }
export type ActivationDelivery = 'email' | 'link'

export function ActivationDeliveryOptions({
  value,
  onChange,
  disabled = false,
}: {
  value: ActivationDelivery
  onChange: (value: ActivationDelivery) => void
  disabled?: boolean
}) {
  const id = useId()
  return (
    <FieldSet disabled={disabled}>
      <FieldLegend variant="label">링크 전달 방법</FieldLegend>
      <RadioGroup value={value} onValueChange={(next) => onChange(next as ActivationDelivery)}>
        <Field orientation="horizontal">
          <RadioGroupItem id={`${id}-email`} value="email" />
          <FieldContent>
            <FieldLabel htmlFor={`${id}-email`}>이메일 발송</FieldLabel>
            <FieldDescription>사용자 이메일로 비밀번호 설정 링크를 보냅니다.</FieldDescription>
          </FieldContent>
        </Field>
        <Field orientation="horizontal">
          <RadioGroupItem id={`${id}-link`} value="link" />
          <FieldContent>
            <FieldLabel htmlFor={`${id}-link`}>링크 직접 전달</FieldLabel>
            <FieldDescription>이메일을 보내지 않고 링크를 복사해 메신저나 문자로 전달합니다.</FieldDescription>
          </FieldContent>
        </Field>
      </RadioGroup>
    </FieldSet>
  )
}

function ActivationLinkResult({ state }: { state: ActivationLinkState }) {
  const { email, outcome } = state
  const url = outcome.activationUrl

  async function copy() {
    if (!url) return
    try {
      await navigator.clipboard.writeText(url)
      toast.success('링크를 복사했습니다.')
    } catch {
      toast.error('복사하지 못했습니다. 링크를 선택해 직접 복사해 주세요.')
    }
  }

  async function share() {
    if (!url) return
    try {
      await navigator.share({ title: 'WorkPass 비밀번호 설정', url })
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) {
        toast.error('공유하지 못했습니다. 링크를 복사해 전달해 주세요.')
      }
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        {outcome.emailed
          ? `${email}으로 링크를 보냈습니다.`
          : '링크를 복사해 메신저나 문자로 전달하세요. 이 링크는 현재 화면에서만 확인할 수 있습니다.'}
      </p>
      {outcome.emailError ? (
        <Alert variant="destructive">
          <AlertDescription>메일 발송에 실패했습니다. 아래 링크를 직접 전달해 주세요.</AlertDescription>
        </Alert>
      ) : null}
      {url ? (
        <div className="flex flex-col gap-2">
          <Input readOnly aria-label="비밀번호 설정 링크" value={url} onFocus={(event) => event.target.select()} />
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => void copy()}>
              <CopyIcon data-icon="inline-start" />링크 복사
            </Button>
            {typeof navigator.share === 'function' ? (
              <Button type="button" variant="outline" onClick={() => void share()}>
                <Share2Icon data-icon="inline-start" />공유
              </Button>
            ) : null}
          </div>
        </div>
      ) : null}
      <p className="text-sm text-muted-foreground">
        {formatDateTime(outcome.expiresAt)}까지 한 번 사용할 수 있습니다.
      </p>
    </div>
  )
}

export function ActivationResultDialog({ state, onClose }: { state: ActivationLinkState | null; onClose: () => void }) {
  return (
    <Dialog open={state !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>비밀번호 설정 링크</DialogTitle>
          <DialogDescription>사용자가 링크에서 비밀번호를 설정한 뒤 로그인할 수 있습니다.</DialogDescription>
        </DialogHeader>
        {state ? <ActivationLinkResult state={state} /> : null}
        <DialogFooter><Button onClick={onClose}>확인</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Mounted for one user; closing discards the one-time link from component state. */
export function ActivationLinkDialog({ user, onClose }: { user: { id: string; email: string }; onClose: () => void }) {
  const [delivery, setDelivery] = useState<ActivationDelivery>('email')
  const issue = useMutation({
    mutationFn: async () => (await apiFetch<{ activation: ActivationOutcome }>(
      `/api/admin/users/${user.id}/activation-link`,
      { method: 'POST', body: JSON.stringify({ sendEmail: delivery === 'email' }) },
    )).activation,
  })

  return (
    <Dialog open onOpenChange={(open) => !open && !issue.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>비밀번호 설정 링크</DialogTitle>
          <DialogDescription>{user.email} 계정의 링크를 이메일로 보내거나 직접 전달하세요.</DialogDescription>
        </DialogHeader>
        {issue.data ? (
          <ActivationLinkResult state={{ email: user.email, outcome: issue.data }} />
        ) : (
          <>
            {issue.error ? <Alert variant="destructive"><AlertDescription>링크를 만들지 못했습니다. 다시 시도해 주세요.</AlertDescription></Alert> : null}
            <ActivationDeliveryOptions value={delivery} onChange={setDelivery} disabled={issue.isPending} />
            <p className="text-xs text-muted-foreground">새 링크를 발급하면 이전에 발급한 미사용 링크는 만료됩니다.</p>
          </>
        )}
        <DialogFooter>
          {issue.data ? <Button onClick={onClose}>확인</Button> : (
            <>
              <Button variant="outline" disabled={issue.isPending} onClick={onClose}>취소</Button>
              <Button disabled={issue.isPending} onClick={() => issue.mutate()}>
                {issue.isPending ? <Spinner data-icon="inline-start" /> : null}
                {delivery === 'email' ? '이메일 발송' : '링크 만들기'}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
