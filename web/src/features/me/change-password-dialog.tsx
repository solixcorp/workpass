import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { useNavigate } from '@tanstack/react-router'
import { useQueryClient } from '@tanstack/react-query'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import {
  confirmCurrentPassword,
  passwordProblem,
  registerNewPassword,
  type ChangeOutcome,
  type PasswordChangeSession,
} from '@/lib/password-change'

const FAILURE: Record<Exclude<ChangeOutcome, 'ok'>, string> = {
  wrong_password: '현재 비밀번호가 맞지 않습니다.',
  rate_limited: '시도가 너무 많습니다. 잠시 뒤에 다시 하세요.',
  expired: '확인 시간이 지났습니다. 현재 비밀번호부터 다시 확인하세요.',
  unavailable: '처리하지 못했습니다. 잠시 뒤에 다시 시도하세요.',
}

/**
 * Two steps: prove the current password, then choose a new one. The server never sees either password;
 * it can only tell that the proof worked, so the new password's rules are checked here.
 */
export function ChangePasswordDialog({ open, onOpenChange, email }: { open: boolean; onOpenChange: (open: boolean) => void; email: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [session, setSession] = useState<PasswordChangeSession | null>(null)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [pending, setPending] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)

  function close(value: boolean) {
    if (pending) return
    if (!value) {
      setSession(null)
      setCurrent('')
      setNext('')
      setAgain('')
      setFailure(null)
    }
    onOpenChange(value)
  }

  async function confirm(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    setPending(true)
    const result = await confirmCurrentPassword(email, current)
    setPending(false)
    setCurrent('')
    if (result.outcome === 'ok' && result.session) setSession(result.session)
    else setFailure(FAILURE[result.outcome === 'ok' ? 'unavailable' : result.outcome])
  }

  async function change(event: FormEvent) {
    event.preventDefault()
    if (!session) return
    setFailure(null)
    const problem = passwordProblem(next, session.rules)
    if (problem) return setFailure(problem)
    if (next !== again) return setFailure('새 비밀번호가 서로 다릅니다.')
    setPending(true)
    const outcome = await registerNewPassword(session, next)
    setPending(false)
    if (outcome !== 'ok') {
      if (outcome === 'expired') setSession(null)
      setFailure(FAILURE[outcome])
      return
    }
    toast.success('비밀번호를 바꿨습니다. 다른 기기에서는 로그아웃됩니다.')
    setNext('')
    setAgain('')
    setSession(null)
    onOpenChange(false)
    await queryClient.invalidateQueries({ queryKey: ['me'] })
    void navigate({ to: '/me' })
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-md">
        {session ? (
          <form onSubmit={change} className="flex flex-col gap-4" noValidate>
            <DialogHeader>
              <DialogTitle>새 비밀번호</DialogTitle>
              <DialogDescription>
                {session.rules.minLength}자 이상으로 정하세요. 바꾸면 다른 기기와 연결된 앱에서는 로그아웃되고, 지금 기기는 그대로입니다.
              </DialogDescription>
            </DialogHeader>
            <FieldGroup>
              <Field data-invalid={failure ? true : undefined}>
                <FieldLabel htmlFor="new-password">새 비밀번호</FieldLabel>
                <Input id="new-password" type="password" autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} autoFocus />
              </Field>
              <Field>
                <FieldLabel htmlFor="new-password-again">새 비밀번호 확인</FieldLabel>
                <Input id="new-password-again" type="password" autoComplete="new-password" value={again} onChange={(event) => setAgain(event.target.value)} />
                <FieldDescription>비밀번호는 이 브라우저 안에서만 처리되어 서버로 보내지지 않습니다.</FieldDescription>
              </Field>
            </FieldGroup>
            {failure ? (
              <Alert variant="destructive">
                <AlertDescription>{failure}</AlertDescription>
              </Alert>
            ) : null}
            <DialogFooter>
              <Button type="button" variant="outline" disabled={pending} onClick={() => close(false)}>취소</Button>
              <Button type="submit" disabled={pending || !next || !again}>
                {pending ? <Spinner data-icon="inline-start" /> : null}
                비밀번호 바꾸기
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <form onSubmit={confirm} className="flex flex-col gap-4" noValidate>
            <DialogHeader>
              <DialogTitle>비밀번호 바꾸기</DialogTitle>
              <DialogDescription>먼저 지금 쓰는 비밀번호를 확인합니다. 확인은 5분 동안만 유효합니다.</DialogDescription>
            </DialogHeader>
            <FieldGroup>
              <Field data-invalid={failure ? true : undefined}>
                <FieldLabel htmlFor="current-password">현재 비밀번호</FieldLabel>
                <Input id="current-password" type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} autoFocus />
              </Field>
            </FieldGroup>
            {failure ? (
              <Alert variant="destructive">
                <AlertDescription>{failure}</AlertDescription>
              </Alert>
            ) : null}
            <DialogFooter>
              <Button type="button" variant="outline" disabled={pending} onClick={() => close(false)}>취소</Button>
              <Button type="submit" disabled={pending || !current}>
                {pending ? <Spinner data-icon="inline-start" /> : null}
                확인
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
