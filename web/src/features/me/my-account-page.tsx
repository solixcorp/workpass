import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from '@tanstack/react-router'
import { KeyRoundIcon, LogOutIcon, MessageSquareIcon, PencilIcon, ShieldCheckIcon } from 'lucide-react'
import { useState, type FormEvent, type ReactNode } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { authClient } from '@/lib/auth-client'
import { myProfileQuery, type MyProfile } from '@/lib/me'
import { sessionQuery } from '@/lib/queries'
import { ChangePasswordDialog } from './change-password-dialog'
import { ConnectedApps } from './connected-apps'
import { VerifyPhoneDialog } from './verify-phone-dialog'

function Row({ label, children, action }: { label: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b py-3 last:border-b-0">
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className="truncate text-sm">{children}</span>
      </div>
      {action}
    </div>
  )
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-1 rounded-2xl border bg-card p-6">
      <h2 className="pb-2 text-sm font-semibold">{title}</h2>
      {children}
    </section>
  )
}

/** The person's own page: personal information, security methods and sessions. */
export function MyAccountPage() {
  const profile = useQuery(myProfileQuery)
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [renaming, setRenaming] = useState(false)
  const [changingPassword, setChangingPassword] = useState(false)
  const [confirm, setConfirm] = useState(false)
  const [verifying, setVerifying] = useState(false)

  const endAll = useMutation({
    mutationFn: async () => {
      const result = await authClient.revokeSessions()
      if (result.error) throw new Error('failed')
    },
    onSuccess: async () => {
      queryClient.clear()
      toast.success('모든 세션을 종료했습니다.')
      await navigate({ to: '/login', replace: true })
    },
    onError: () => {
      toast.error('세션을 종료하지 못했습니다.')
      setConfirm(false)
    },
  })

  if (profile.isPending) {
    return (
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-56 w-full" />
      </div>
    )
  }
  if (profile.error) {
    return (
      <div className="mx-auto w-full max-w-3xl">
        <Alert variant="destructive">
          <AlertDescription>내 정보를 불러오지 못했습니다.</AlertDescription>
        </Alert>
      </div>
    )
  }
  const me = profile.data

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6">
      <h1 className="text-xl font-semibold">내 정보</h1>

      <Card title="개인 정보">
        <Row
          label="이름"
          action={
            <Button variant="outline" size="sm" onClick={() => setRenaming(true)}>
              <PencilIcon data-icon="inline-start" />
              수정
            </Button>
          }
        >
          {me.name}
        </Row>
        <Row label="이메일">{me.email}</Row>
        <Row label="로그인 이름">{me.login}</Row>
        <Row
          label="휴대전화"
          action={
            <div className="flex items-center gap-2">
              {me.phoneNumber && !me.phoneVerified ? (
                <Button variant="default" size="sm" disabled={!me.smsAvailable} title={me.smsAvailable ? undefined : '문자 발송이 설정되어 있지 않습니다'} onClick={() => setVerifying(true)}>
                  <MessageSquareIcon data-icon="inline-start" />
                  번호 확인
                </Button>
              ) : null}
              <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                <PencilIcon data-icon="inline-start" />
                {me.phoneNumber ? '수정' : '추가'}
              </Button>
            </div>
          }
        >
          {me.phoneNumber ? (
            <span className="flex items-center gap-2">
              {me.phoneNumber}
              {me.phoneVerified ? <Badge variant="secondary">확인됨</Badge> : <Badge variant="outline">확인 전</Badge>}
            </span>
          ) : (
            <span className="text-muted-foreground">등록하지 않았습니다</span>
          )}
        </Row>
        {me.fields.title || me.fields.department || me.fields.organization || me.fields.manager ? (
          <>
            {me.fields.title ? <Row label="직함">{me.fields.title}</Row> : null}
            {me.fields.department ? <Row label="부서">{me.fields.department}</Row> : null}
            {me.fields.organization ? <Row label="조직">{me.fields.organization}</Row> : null}
            {me.fields.manager ? <Row label="관리자">{me.fields.manager}</Row> : null}
          </>
        ) : null}
        <p className="pt-3 text-xs text-muted-foreground">직함과 부서 같은 업무 정보는 관리자가 관리합니다. 확인을 마친 번호만 2차 인증 코드를 받는 데 쓰입니다.{me.phoneNumber && !me.phoneVerified && !me.smsAvailable ? ' 지금은 문자 발송이 설정되어 있지 않아 번호를 확인할 수 없습니다.' : ''}</p>
      </Card>

      <Card title="보안 방법">
        <Row
          label="비밀번호"
          action={
            <Button variant="outline" size="sm" onClick={() => setChangingPassword(true)}>
              <KeyRoundIcon data-icon="inline-start" />
              바꾸기
            </Button>
          }
        >
          바꾸면 다른 기기에서는 로그아웃됩니다.
        </Row>
        <Row
          label="2차 인증"
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/security">
                <ShieldCheckIcon data-icon="inline-start" />
                관리
              </Link>
            </Button>
          }
        >
          {me.twoFactorEnabled ? '사용 중' : '사용하지 않음'}
        </Row>
        <p className="pt-3 text-xs text-muted-foreground">패스키, 인증 앱, 보안 토큰과 신뢰한 기기는 보안 화면에서 관리합니다.</p>
      </Card>

      <ConnectedApps />

      <Card title="세션">
        <Row
          label="로그인한 모든 기기"
          action={
            <Button variant="outline" size="sm" onClick={() => setConfirm(true)}>
              <LogOutIcon data-icon="inline-start" />
              모든 세션 종료
            </Button>
          }
        >
          지금 쓰는 기기를 포함해 모든 기기에서 로그아웃합니다.
        </Row>
      </Card>

      {me.phoneNumber ? <VerifyPhoneDialog key={`verify-${verifying}`} open={verifying} phone={me.phoneNumber} onClose={() => setVerifying(false)} /> : null}
      <PhoneDialog key={String(editing)} open={editing} onOpenChange={setEditing} me={me} />
      <ChangePasswordDialog key={`pw-${changingPassword}`} open={changingPassword} onOpenChange={setChangingPassword} email={me.email} />
      <NameDialog key={`name-${renaming}`} open={renaming} onOpenChange={setRenaming} me={me} />
      <AlertDialog open={confirm} onOpenChange={(open) => !endAll.isPending && setConfirm(open)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>모든 세션을 종료할까요?</AlertDialogTitle>
            <AlertDialogDescription>이 기기를 포함해 로그인해 둔 모든 기기에서 로그아웃되고, 다시 로그인해야 합니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={endAll.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={endAll.isPending}
              onClick={(event) => {
                event.preventDefault()
                endAll.mutate()
              }}
            >
              세션 종료
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function NameDialog({ open, onOpenChange, me }: { open: boolean; onOpenChange: (open: boolean) => void; me: MyProfile }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState(me.name)
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () => apiFetch('/api/me/profile', { method: 'PUT', body: JSON.stringify({ name: name.trim() }) }),
    onSuccess: async () => {
      toast.success('이름을 저장했습니다.')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: myProfileQuery.queryKey }),
        queryClient.invalidateQueries({ queryKey: sessionQuery.queryKey }),
      ])
      onOpenChange(false)
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    if (!name.trim()) {
      setFailure('이름을 입력하세요.')
      return
    }
    save.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !save.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>이름 수정</DialogTitle>
            <DialogDescription>다른 사람에게 보이는 이름입니다. 로그인에 쓰는 이메일은 관리자만 바꿀 수 있습니다.</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field data-invalid={failure ? true : undefined}>
              <FieldLabel htmlFor="my-name">이름</FieldLabel>
              <Input id="my-name" autoComplete="name" maxLength={128} value={name} onChange={(event) => setName(event.target.value)} />
            </Field>
          </FieldGroup>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={save.isPending} onClick={() => onOpenChange(false)}>
              취소
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? <Spinner data-icon="inline-start" /> : null}
              저장
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function PhoneDialog({ open, onOpenChange, me }: { open: boolean; onOpenChange: (open: boolean) => void; me: MyProfile }) {
  const queryClient = useQueryClient()
  const [phone, setPhone] = useState(me.phoneNumber ?? '')
  const [failure, setFailure] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () => apiFetch('/api/me/profile', { method: 'PUT', body: JSON.stringify({ phoneNumber: phone.trim() }) }),
    onSuccess: async () => {
      toast.success(phone.trim() ? '휴대전화 번호를 저장했습니다.' : '휴대전화 번호를 지웠습니다.')
      await queryClient.invalidateQueries({ queryKey: myProfileQuery.queryKey })
      onOpenChange(false)
    },
    onError: (error) => setFailure(error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : '저장하지 못했습니다.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    save.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !save.isPending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>휴대전화</DialogTitle>
            <DialogDescription>한국 휴대전화 번호(010)만 쓸 수 있고 숫자만 적습니다. 비워 두고 저장하면 번호를 지웁니다.</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="my-phone">휴대전화 번호</FieldLabel>
              <Input id="my-phone" inputMode="tel" autoComplete="tel" placeholder="01012345678" value={phone} onChange={(event) => setPhone(event.target.value)} />
              <FieldDescription>번호를 바꾸면 확인 전 상태로 돌아갑니다.</FieldDescription>
            </Field>
          </FieldGroup>
          {failure ? (
            <Alert variant="destructive">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={save.isPending} onClick={() => onOpenChange(false)}>
              취소
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? <Spinner data-icon="inline-start" /> : null}
              저장
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
