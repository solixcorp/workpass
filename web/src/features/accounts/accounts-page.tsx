import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BuildingIcon, CheckIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '@/components/ui/empty'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemMedia, ItemTitle } from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { apiFetch } from '@/lib/api'
import { ROLE_LABELS, type Membership } from '@/lib/accounts'
import { formatDateTime } from '@/lib/format'

export const accountsKey = ['accounts'] as const

export function useAccounts() {
  return useQuery({
    queryKey: accountsKey,
    queryFn: () =>
      apiFetch<{ accounts: Membership[]; activeAccountId: string | null }>('/api/accounts'),
  })
}

export function AccountsPage() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useAccounts()

  const switchTo = useMutation({
    mutationFn: (accountId: string) =>
      apiFetch('/api/accounts/switch', { method: 'POST', body: JSON.stringify({ accountId }) }),
    onSuccess: async () => {
      toast.success('활성 계정을 바꿨습니다.')
      await queryClient.invalidateQueries({ queryKey: accountsKey })
    },
    onError: () => toast.error('계정을 바꾸지 못했습니다.'),
  })

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-8">
      <h1 className="text-2xl font-semibold">계정</h1>

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-muted-foreground">내 계정</h2>
        <p className="text-sm text-muted-foreground">
          여러 계정(조직 단위)에 속해 있으면 지금 일하는 계정을 고릅니다. 선택은 이 로그인 세션에만 적용됩니다.
        </p>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>계정 목록을 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : isPending ? (
          <Skeleton className="h-20 rounded-xl" />
        ) : data.accounts.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>속한 계정이 없습니다</EmptyTitle>
              <EmptyDescription>초대 코드를 받았다면 아래에서 입력해 참여하세요.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <ItemGroup className="gap-2">
            {data.accounts.map((membership) => (
              <Item key={membership.account.id} variant="outline">
                <ItemMedia variant="icon">
                  <BuildingIcon />
                </ItemMedia>
                <ItemContent>
                  <ItemTitle>
                    {membership.account.name}
                    <Badge variant="outline">{ROLE_LABELS[membership.role]}</Badge>
                    {membership.active ? <Badge>사용 중</Badge> : null}
                  </ItemTitle>
                  <ItemDescription>
                    {membership.account.description || `${formatDateTime(membership.grantedAt)}에 참여`}
                  </ItemDescription>
                </ItemContent>
                <ItemActions>
                  {membership.active ? (
                    <CheckIcon className="text-muted-foreground" aria-label="사용 중" />
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={switchTo.isPending}
                      onClick={() => switchTo.mutate(membership.account.id)}
                    >
                      이 계정으로 전환
                    </Button>
                  )}
                </ItemActions>
              </Item>
            ))}
          </ItemGroup>
        )}
      </section>

      <JoinSection />
    </div>
  )
}

function JoinSection() {
  const queryClient = useQueryClient()
  const [token, setToken] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const join = useMutation({
    mutationFn: () =>
      apiFetch<{ account: { name: string } }>('/api/accounts/join', {
        method: 'POST',
        body: JSON.stringify({ token: token.trim() }),
      }),
    onSuccess: async (result) => {
      toast.success(`${result.account.name} 계정에 참여했습니다.`)
      setToken('')
      setFailure(null)
      await queryClient.invalidateQueries({ queryKey: accountsKey })
    },
    // The server answers every bad code the same way; so does the screen.
    onError: () => setFailure('초대 코드를 사용할 수 없습니다. 코드를 확인하거나 새 초대를 요청하세요.'),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    join.mutate()
  }

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-medium text-muted-foreground">초대 코드로 참여</h2>
      <form onSubmit={submit} noValidate>
        <FieldGroup>
          <Field data-invalid={failure ? true : undefined}>
            <FieldLabel htmlFor="join-token">초대 코드</FieldLabel>
            <div className="flex gap-2">
              <Input
                id="join-token"
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                value={token}
                onChange={(event) => setToken(event.target.value)}
              />
              <Button type="submit" disabled={join.isPending || !token.trim()}>
                {join.isPending ? <Spinner data-icon="inline-start" /> : null}
                참여
              </Button>
            </div>
            <FieldDescription>코드는 한 번만 쓸 수 있습니다.</FieldDescription>
            {failure ? <FieldError>{failure}</FieldError> : null}
          </Field>
        </FieldGroup>
      </form>
    </section>
  )
}
