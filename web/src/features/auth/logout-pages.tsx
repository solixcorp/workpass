import { useSearch } from '@tanstack/react-router'
import { LogOutIcon } from 'lucide-react'
import { AuthShell } from '@/components/auth-shell'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

/**
 * Where an app's "log out" lands. The server keeps the decision (a signed,
 * short-lived confirmation); this only asks the person and posts it back as
 * a plain form, so the provider's cookie travels with it.
 */
export function LogoutConfirmPage() {
  return (
    <AuthShell heading="로그아웃" badge={<LogOutIcon />}>
      <p className="text-center text-sm text-muted-foreground">이 계정에서 로그아웃할까요? 이 계정으로 로그인한 앱에서도 함께 로그아웃됩니다.</p>
      <form method="post" action="/api/auth/oauth2/end-session/confirm" className="flex flex-col gap-3">
        <Button type="submit" name="action" value="confirm">
          로그아웃
        </Button>
        <Button type="button" variant="outline" onClick={() => window.location.assign('/')}>
          취소
        </Button>
      </form>
    </AuthShell>
  )
}

export function LoggedOutPage() {
  const { error, redirect } = useSearch({ from: '/logged-out' })
  return (
    <AuthShell heading={error ? '로그아웃하지 못했습니다' : '로그아웃되었습니다'} badge={<LogOutIcon />}>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>로그아웃 요청을 처리하지 못했습니다. 로그아웃을 요청한 앱에서 다시 시도하세요.</AlertDescription>
        </Alert>
      ) : (
        <p className="text-center text-sm text-muted-foreground">
          {redirect === 'invalid'
            ? '앱이 요청한 이동 주소가 등록되어 있지 않아 이 화면에 머뭅니다.'
            : '안전하게 로그아웃했습니다.'}
        </p>
      )}
      <Button type="button" onClick={() => window.location.assign('/')}>
        다시 로그인
      </Button>
    </AuthShell>
  )
}
