import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'

/** A free-text message to the administrators about an app the person needs. */
export function RequestAppDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [message, setMessage] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const send = useMutation({
    mutationFn: () => apiFetch('/api/me/app-requests', { method: 'POST', body: JSON.stringify({ message: message.trim() }) }),
    onSuccess: () => {
      toast.success('관리자에게 보냈습니다.')
      setMessage('')
      setFailure(null)
      onOpenChange(false)
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '보내지 못했습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    send.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !send.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>앱 접근 요청</DialogTitle>
            <DialogDescription>필요한 앱과 이유를 관리자에게 알립니다.</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="app-request-message">내용</FieldLabel>
              <Textarea id="app-request-message" rows={4} maxLength={500} value={message} onChange={(event) => setMessage(event.target.value)} placeholder="예: 디자인 작업에 Figma가 필요합니다." />
              <FieldDescription>정해진 승인 절차가 있는 앱은 접근 요청 화면에서 바로 요청할 수 있습니다.</FieldDescription>
            </Field>
          </FieldGroup>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={send.isPending} onClick={() => onOpenChange(false)}>
              취소
            </Button>
            <Button type="submit" disabled={send.isPending || !message.trim()}>
              {send.isPending ? <Spinner data-icon="inline-start" /> : null}
              보내기
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
