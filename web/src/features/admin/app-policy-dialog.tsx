import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemActions, ItemContent, ItemDescription, ItemTitle } from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { ApiError, apiFetch } from '@/lib/api'

type Policy = {
  subject: string
  allowedMethods: string
  sessionTtlSeconds: number | null
  bypassWindowSeconds: number
  enforcementMode: 'enforce' | 'observe'
  requireMfa: boolean
  /** Which second factors count for this app; empty means any the person has. */
  mfaMethods?: string[]
  groups: string[]
  requiredAccount: string | null
}

type Group = { id: string; name: string }

export type PolicyApp = { slug: string; name: string }

const METHODS = [
  { key: 'password', label: '비밀번호' },
  { key: 'passkey', label: '패스키' },
] as const

type MfaMethod = { id: string; label: string; enabledGlobally: boolean }

/** Used until the server says which methods exist and which are switched on. */
const FALLBACK_MFA_METHODS: MfaMethod[] = [
  { id: 'totp', label: '인증 앱(TOTP)', enabledGlobally: true },
  { id: 'hotp', label: '보안 토큰(HOTP)', enabledGlobally: true },
  { id: 'duo', label: 'Duo', enabledGlobally: true },
  { id: 'passkey', label: '패스키', enabledGlobally: true },
  { id: 'email', label: '이메일 코드', enabledGlobally: true },
  { id: 'sms', label: '문자(SMS) 코드', enabledGlobally: true },
]

const DEFAULT_POLICY = (subject: string): Policy => ({
  subject,
  allowedMethods: 'password,passkey',
  sessionTtlSeconds: null,
  bypassWindowSeconds: 28800,
  enforcementMode: 'enforce',
  requireMfa: false,
  mfaMethods: [],
  groups: [],
  requiredAccount: null,
})

/** Who can open an app and how they must have signed in: groups, methods, second factor, session length. */
export function AppPolicyDialog({ app, onClose }: { app: PolicyApp | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const subject = app ? `app:${app.slug}` : ''
  const [draft, setDraft] = useState<Policy | null>(null)
  const [ttlMinutes, setTtlMinutes] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const stored = useQuery({
    queryKey: ['admin', 'app-policy', subject],
    enabled: app !== null,
    queryFn: async () => {
      const { policies, availableMfaMethods } = await apiFetch<{ policies: Policy[]; availableMfaMethods?: MfaMethod[] }>('/api/admin/app-access-policies')
      return { policy: policies.find((policy) => policy.subject === subject) ?? null, methods: availableMfaMethods ?? FALLBACK_MFA_METHODS }
    },
  })

  const groups = useQuery({
    queryKey: ['admin', 'groups'],
    enabled: app !== null,
    queryFn: () => apiFetch<{ groups: Group[] }>('/api/admin/directory-groups?limit=100'),
  })

  useEffect(() => {
    if (!app || stored.isPending) return
    const base = stored.data?.policy ?? DEFAULT_POLICY(subject)
    setDraft(base)
    setTtlMinutes(base.sessionTtlSeconds ? String(Math.round(base.sessionTtlSeconds / 60)) : '')
    setFailure(null)
  }, [app, subject, stored.data, stored.isPending])

  const mfaMethods = stored.data?.methods ?? FALLBACK_MFA_METHODS

  const save = useMutation({
    mutationFn: (policy: Policy) =>
      apiFetch('/api/admin/app-access-policies', { method: 'PUT', body: JSON.stringify(policy) }),
    onSuccess: async () => {
      toast.success('접근 정책을 저장했습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'app-policy', subject] })
      onClose()
    },
    onError: (cause: unknown) => setFailure(cause instanceof ApiError ? cause.message : '저장하지 못했습니다.'),
  })

  const clear = useMutation({
    mutationFn: () => apiFetch(`/api/admin/app-access-policies/${encodeURIComponent(subject)}`, { method: 'DELETE' }),
    onSuccess: async () => {
      toast.success('접근 정책을 지웠습니다. 로그인한 모든 사용자가 열 수 있습니다.')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'app-policy', subject] })
      onClose()
    },
    onError: () => setFailure('정책을 지우지 못했습니다.'),
  })

  function update(patch: Partial<Policy>) {
    setDraft((current) => (current ? { ...current, ...patch } : current))
  }

  function toggleMethod(key: string, on: boolean) {
    if (!draft) return
    const current = new Set(draft.allowedMethods.split(',').filter(Boolean))
    if (on) current.add(key)
    else current.delete(key)
    update({ allowedMethods: [...current].join(',') })
  }

  function toggleGroup(id: string, on: boolean) {
    if (!draft) return
    update({ groups: on ? [...draft.groups, id] : draft.groups.filter((group) => group !== id) })
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!draft) return
    setFailure(null)
    const minutes = ttlMinutes.trim()
    let sessionTtlSeconds: number | null = null
    if (minutes) {
      const value = Number(minutes)
      if (!Number.isInteger(value) || value < 1 || value > 720) {
        setFailure('세션 시간은 1분에서 720분(12시간) 사이의 정수로 입력하세요.')
        return
      }
      sessionTtlSeconds = value * 60
    }
    if (!draft.allowedMethods) {
      setFailure('로그인 방식을 하나 이상 허용하세요.')
      return
    }
    save.mutate({ ...draft, sessionTtlSeconds })
  }

  const methods = new Set(draft?.allowedMethods.split(',').filter(Boolean))
  const busy = save.isPending || clear.isPending
  const protocolNote =
    app && draft && stored.data !== undefined
      ? 'SAML, WS-Fed, OIDC 앱의 실제 로그인은 각 프로토콜의 접근 정책으로 따로 막습니다.'
      : null
  const groupList = groups.data?.groups ?? []

  return (
    <Dialog open={app !== null} onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{app?.name} 접근 정책</DialogTitle>
          <DialogDescription>사용자의 앱 목록에 이 앱이 보이는 조건입니다. 정책이 없으면 로그인한 모든 사용자에게 보입니다.</DialogDescription>
        </DialogHeader>

        {stored.error ? (
          <Alert variant="destructive">
            <AlertDescription>정책을 불러오지 못했습니다.</AlertDescription>
          </Alert>
        ) : !draft ? (
          <Skeleton className="h-48 rounded-lg" />
        ) : (
          <form id="app-policy" onSubmit={submit} noValidate className="max-h-[60vh] overflow-y-auto pr-1">
            <FieldGroup>
              {protocolNote ? (
                <Alert>
                  <AlertDescription>{protocolNote}</AlertDescription>
                </Alert>
              ) : null}
              <FieldSet>
                <FieldLegend variant="label">허용할 그룹</FieldLegend>
                <FieldDescription>
                  {groupList.length === 0
                    ? '그룹이 없습니다. 그룹 메뉴에서 먼저 만드세요.'
                    : '아무것도 고르지 않으면 모든 사용자가 열 수 있고, 고르면 그 그룹의 멤버만 열 수 있습니다.'}
                </FieldDescription>
                {groupList.map((group) => (
                  <Item key={group.id} variant="outline" size="sm">
                    <ItemContent>
                      <ItemTitle>{group.name}</ItemTitle>
                    </ItemContent>
                    <ItemActions>
                      <Switch
                        aria-label={`${group.name} 그룹 허용`}
                        checked={draft.groups.includes(group.id)}
                        onCheckedChange={(on) => toggleGroup(group.id, on)}
                      />
                    </ItemActions>
                  </Item>
                ))}
              </FieldSet>

              <FieldSet>
                <FieldLegend variant="label">허용할 로그인 방식</FieldLegend>
                {METHODS.map((method) => (
                  <Item key={method.key} variant="outline" size="sm">
                    <ItemContent>
                      <ItemTitle>{method.label}</ItemTitle>
                    </ItemContent>
                    <ItemActions>
                      <Switch
                        aria-label={`${method.label} 허용`}
                        checked={methods.has(method.key)}
                        onCheckedChange={(on) => toggleMethod(method.key, on)}
                      />
                    </ItemActions>
                  </Item>
                ))}
              </FieldSet>

              <Item variant="outline" size="sm">
                <ItemContent>
                  <ItemTitle>2차 인증 필수</ItemTitle>
                  <ItemDescription>이 앱을 열 때마다 2차 인증을 마친 세션이어야 합니다.</ItemDescription>
                </ItemContent>
                <ItemActions>
                  <Switch aria-label="2차 인증 필수" checked={draft.requireMfa} onCheckedChange={(on) => update({ requireMfa: on })} />
                </ItemActions>
              </Item>

              {draft.requireMfa ? (
                <FieldSet>
                  <FieldLegend variant="label">인정할 2차 인증 방식</FieldLegend>
                  <FieldDescription>
                    고른 방식 중 하나로 확인한 세션만 이 앱을 열 수 있습니다. 하나도 고르지 않으면 사용자가 가진 어떤 방식이든 됩니다. 사용자가 고른 방식을 하나도 갖고 있지 않으면 이 앱을 열 수 없으니, 먼저 보안 설정에서 등록하게 안내하세요.
                  </FieldDescription>
                  <FieldGroup className="gap-3">
                    {mfaMethods.map((method) => (
                      <Field key={method.id} orientation="horizontal">
                        <Checkbox
                          id={`mfa-method-${method.id}`}
                          disabled={!method.enabledGlobally}
                          checked={(draft.mfaMethods ?? []).includes(method.id)}
                          onCheckedChange={(on) =>
                            setDraft((current) => {
                              if (!current) return current
                              const rest = (current.mfaMethods ?? []).filter((id) => id !== method.id)
                              return { ...current, mfaMethods: on === true ? [...rest, method.id] : rest }
                            })
                          }
                        />
                        <FieldLabel htmlFor={`mfa-method-${method.id}`}>
                          {method.label}
                          {!method.enabledGlobally ? <span className="ml-2 text-xs font-normal text-muted-foreground">조직 설정에서 꺼져 있음</span> : null}
                        </FieldLabel>
                      </Field>
                    ))}
                  </FieldGroup>
                </FieldSet>
              ) : null}

              <Item variant="outline" size="sm">
                <ItemContent>
                  <ItemTitle>관찰 모드</ItemTitle>
                  <ItemDescription>켜면 정책이 막을 경우를 기록만 하고 실제로는 막지 않습니다. 적용 전 점검용입니다.</ItemDescription>
                </ItemContent>
                <ItemActions>
                  <Switch
                    aria-label="관찰 모드"
                    checked={draft.enforcementMode === 'observe'}
                    onCheckedChange={(on) => update({ enforcementMode: on ? 'observe' : 'enforce' })}
                  />
                </ItemActions>
              </Item>

              <Field data-invalid={failure ? true : undefined}>
                <FieldLabel htmlFor="policy-ttl">세션 시간 제한</FieldLabel>
                <div className="flex items-center gap-2">
                  <Input
                    id="policy-ttl"
                    type="number"
                    inputMode="numeric"
                    className="w-32"
                    min={1}
                    max={720}
                    placeholder="제한 없음"
                    value={ttlMinutes}
                    onChange={(event) => setTtlMinutes(event.target.value)}
                  />
                  <span className="text-sm text-muted-foreground">분</span>
                </div>
                <FieldDescription>비워 두면 제한하지 않습니다. 최대 720분입니다.</FieldDescription>
                {failure ? <FieldError>{failure}</FieldError> : null}
              </Field>
            </FieldGroup>
          </form>
        )}

        <DialogFooter className="sm:justify-between">
          <Button
            type="button"
            variant="outline"
            disabled={busy || !stored.data}
            onClick={() => clear.mutate()}
          >
            정책 지우기
          </Button>
          <div className="flex gap-2">
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              취소
            </Button>
            <Button type="submit" form="app-policy" disabled={busy || !draft}>
              {save.isPending ? <Spinner data-icon="inline-start" /> : null}
              저장
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
