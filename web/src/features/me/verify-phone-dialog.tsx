import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { myProfileQuery } from '@/lib/me'

const errorText = (error: unknown, fallback: string) => (error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : fallback)

/** Prove the saved number is the person's own: a code is texted to it, and typing it back marks it verified. */
export function VerifyPhoneDialog({ open, phone, onClose }: { open: boolean; phone: string; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [sent, setSent] = useState(false)
  const [code, setCode] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  const [wait, setWait] = useState(0)

  useEffect(() => {
    if (wait <= 0) return
    const timer = setTimeout(() => setWait(wait - 1), 1000)
    return () => clearTimeout(timer)
  }, [wait])

  const send = useMutation({
    mutationFn: () => apiFetch('/api/me/phone/send-code', { method: 'POST', body: '{}' }),
    onSuccess: () => {
      setSent(true)
      setCode('')
      setFailure(null)
      setWait(60)
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 429) {
        const retry = (error.body as { retryAfterSeconds?: number } | null)?.retryAfterSeconds
        if (retry) setWait(retry)
      }
      setFailure(errorText(error, '코드를 보내지 못했습니다.'))
    },
  })
  const verify = useMutation({
    mutationFn: () => apiFetch('/api/me/phone/verify', { method: 'POST', body: JSON.stringify({ code }) }),
    onSuccess: async () => {
      toast.success('휴대전화 번호를 확인했습니다.')
      await queryClient.invalidateQueries({ queryKey: myProfileQuery.queryKey })
      onClose()
    },
    onError: (error) => {
      const left = (error instanceof ApiError ? (error.body as { attemptsLeft?: number } | null)?.attemptsLeft : undefined)
      setFailure(`${errorText(error, '확인하지 못했습니다.')}${left !== undefined ? ` 남은 시도 ${left}번` : ''}`)
      setCode('')
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    if (code.length === 6) verify.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !verify.isPending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>휴대전화 번호 확인</DialogTitle>
            <DialogDescription>
              {sent ? `${phone}(으)로 보낸 6자리 코드를 입력하세요. 코드는 10분 동안 쓸 수 있습니다.` : `${phone}(으)로 6자리 인증 코드를 문자로 보냅니다.`}
            </DialogDescription>
          </DialogHeader>
          {sent ? (
            <div className="flex justify-center py-2">
              <InputOTP maxLength={6} value={code} onChange={setCode} autoFocus autoComplete="one-time-code" data-1p-ignore inputMode="numeric" aria-label="인증 코드">
                <InputOTPGroup>
                  {Array.from({ length: 6 }, (_, index) => (
                    <InputOTPSlot key={index} index={index} />
                  ))}
                </InputOTPGroup>
              </InputOTP>
            </div>
          ) : null}
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={verify.isPending} onClick={onClose}>
              닫기
            </Button>
            {sent ? (
              <>
                <Button type="button" variant="ghost" disabled={send.isPending || wait > 0} onClick={() => send.mutate()}>
                  {wait > 0 ? `다시 보내기 (${wait}초)` : '다시 보내기'}
                </Button>
                <Button type="submit" disabled={verify.isPending || code.length !== 6}>
                  {verify.isPending ? <Spinner data-icon="inline-start" /> : null}
                  확인
                </Button>
              </>
            ) : (
              <Button type="button" disabled={send.isPending} onClick={() => send.mutate()}>
                {send.isPending ? <Spinner data-icon="inline-start" /> : null}
                코드 보내기
              </Button>
            )}
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
