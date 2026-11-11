import { useMutation, useQuery } from '@tanstack/react-query'
import { ShieldCheckIcon } from 'lucide-react'
import { useState } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ApiError, apiFetch } from '@/lib/api'
import { ApprovalCard, ScopeList } from './approval-card'

type ConsentContext = {
  allowed: boolean
  application: { name: string; description: string | null; icon: string | null }
  scopes: string[]
  account: { name: string; email: string }
}

/** The signed request from the authorization endpoint, exactly as it arrived. */
const oauthQuery = () => new URLSearchParams(window.location.search).toString()

/**
 * Asks whether an app may sign the person in and what it may read. The query
 * is signed by the server and sent back untouched, so nothing here can change
 * what is being approved.
 */
export function ConsentPage() {
  const [failure, setFailure] = useState<string | null>(null)
  const context = useQuery({
    queryKey: ['consent', window.location.search],
    queryFn: () => apiFetch<ConsentContext>(`/api/consent/context?${oauthQuery()}`),
    retry: false,
  })

  const decide = useMutation({
    mutationFn: async (accept: boolean) => {
      const result = await apiFetch<{ redirectURI?: string; url?: string }>('/api/auth/oauth2/consent', {
        method: 'POST',
        body: JSON.stringify({ oauth_query: oauthQuery(), accept, scopes: context.data?.scopes ?? [] }),
      })
      const target = result.redirectURI ?? result.url
      if (!target) throw new Error('no target')
      return target
    },
    onSuccess: (target) => window.location.assign(target),
    onError: (error) =>
      setFailure(
        error instanceof ApiError && error.status === 403
          ? '이 로그인 요청은 계속할 수 없습니다.'
          : error instanceof ApiError && error.status === 401
            ? '로그인이 끝났습니다. 앱에서 다시 시작하세요.'
            : '이 로그인 요청을 처리할 수 없습니다. 앱에서 새 요청을 시작하세요.',
      ),
  })

  if (context.isPending) {
    return (
      <ApprovalCard>
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-24 w-full" />
      </ApprovalCard>
    )
  }
  if (context.error) {
    const signedOut = context.error instanceof ApiError && context.error.status === 401
    return (
      <ApprovalCard>
        <h1 className="text-lg font-semibold">계속할 수 없습니다</h1>
        <Alert variant="destructive">
          <AlertDescription>{signedOut ? '로그인 상태가 아닙니다. 앱으로 돌아가 다시 로그인하세요.' : '이 로그인 요청을 처리할 수 없습니다. 앱에서 새 요청을 시작하세요.'}</AlertDescription>
        </Alert>
      </ApprovalCard>
    )
  }

  const { application, scopes, account, allowed } = context.data
  if (!allowed) {
    return (
      <ApprovalCard>
        <h1 className="text-lg font-semibold">{application.name}을(를) 열 수 없습니다</h1>
        <Alert>
          <AlertDescription>이 계정({account.email})에는 이 앱을 쓸 권한이 없습니다. 필요하면 관리자에게 요청하세요.</AlertDescription>
        </Alert>
      </ApprovalCard>
    )
  }

  return (
    <ApprovalCard>
      <div className="flex flex-col items-center gap-3 text-center">
        {application.icon ? <img src={application.icon} alt="" className="size-12 rounded-xl border object-contain" /> : <ShieldCheckIcon className="size-10 text-muted-foreground" />}
        <h1 className="text-lg font-semibold">{application.name}에 계속할까요?</h1>
        <p className="text-sm text-muted-foreground">{application.description ?? `${account.name}(${account.email}) 계정으로 로그인합니다.`}</p>
      </div>
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">이 앱이 요청하는 권한</h2>
        <ScopeList scopes={scopes} />
      </section>
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <div className="flex flex-col gap-2">
        <Button disabled={decide.isPending} onClick={() => { setFailure(null); decide.mutate(true) }}>
          {decide.isPending ? <Spinner data-icon="inline-start" /> : null}
          허용하고 계속
        </Button>
        <Button variant="outline" disabled={decide.isPending} onClick={() => { setFailure(null); decide.mutate(false) }}>
          허용하지 않음
        </Button>
      </div>
    </ApprovalCard>
  )
}
