import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLinkIcon, PencilIcon, RefreshCwIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'
import {
  CLIENT_TYPE_LABELS,
  discoveryQuery,
  GRANT_LABELS,
  integrationKey,
  integrationQuery,
  type Integration,
  type OidcClient,
} from '@/lib/integrations'
import {
  draftFromClient,
  OidcFields,
  oidcBody,
  oidcDraftProblem,
  type OidcDraft,
} from './oidc-fields'
import { SecretDialog } from './new-integration-page'
import { CopyField, Section, SettingRow } from './parts'

function explain(error: unknown, fallback: string) {
  return error instanceof ApiError && /[가-힣]/.test(error.message) ? error.message : fallback
}

const SCOPE_LABELS: Record<string, string> = {
  openid: '기본 신원 정보',
  profile: '프로필',
  email: '이메일',
  phone: '전화번호',
  groups: '그룹',
  offline_access: '오래 유지되는 접근(리프레시 토큰)',
}

function ValueList({ values, empty = '없음' }: { values: string[]; empty?: string }) {
  if (values.length === 0) return <span className="text-sm text-muted-foreground">{empty}</span>
  return (
    <ul className="flex flex-col gap-1">
      {values.map((value) => (
        <li key={value} className="break-all font-mono text-xs">
          {value}
        </li>
      ))}
    </ul>
  )
}

/** The protocol settings of one app: what the app needs to connect, and what this system gives it. */
export function SignOnPanel({ slug, name, protocol }: { slug: string; name: string; protocol: string }) {
  const { data, isPending, error } = useQuery(integrationQuery(slug))
  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>연동 정보를 불러오지 못했습니다.</AlertDescription>
      </Alert>
    )
  }
  if (isPending) return <Skeleton className="h-64 rounded-2xl" />
  if (protocol === 'oidc' && data.oidc) return <OidcPanel slug={slug} client={data.oidc} />
  if (protocol === 'saml') return <SamlPanel slug={slug} data={data} />
  if (protocol === 'wsfed') return <WsfedPanel slug={slug} data={data} />
  if (protocol === 'swa' && data.swa) {
    return (
      <Section title="SWA 설정">
        <SettingRow title="사이트 주소" description="이 사이트에서만 자동 로그인이 동작합니다.">
          <CopyField label="사이트 주소" value={data.swa.origin} />
        </SettingRow>
      </Section>
    )
  }
  return (
    <Section title="로그인 방식">
      <SettingRow title={name} description="이 앱은 로그인 연동 없이 링크만 보여 줍니다.">
        <span className="text-sm text-muted-foreground">연동 설정이 없습니다.</span>
      </SettingRow>
    </Section>
  )
}

function OidcPanel({ slug, client }: { slug: string; client: OidcClient }) {
  const queryClient = useQueryClient()
  const discovery = useQuery(discoveryQuery)
  const [editing, setEditing] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState(false)
  const [rotated, setRotated] = useState<string | null>(null)

  const rotate = useMutation({
    mutationFn: () => apiFetch<{ clientSecret: string }>(`/api/admin/oidc-clients/${client.clientId}/rotate-secret`, { method: 'POST' }),
    onSuccess: (result) => {
      setConfirmRotate(false)
      setRotated(result.clientSecret)
    },
    onError: () => toast.error('비밀키를 새로 발급하지 못했습니다.'),
  })

  const d = discovery.data
  const endpoints: Array<[string, string | undefined]> = [
    ['발급자(Issuer)', d?.issuer],
    ['인증 엔드포인트', d?.authorization_endpoint],
    ['토큰 엔드포인트', d?.token_endpoint],
    ['사용자 정보 엔드포인트', d?.userinfo_endpoint],
    ['공개 키(JWKS)', d?.jwks_uri],
    ['로그아웃 엔드포인트', d?.end_session_endpoint],
  ]

  return (
    <div className="flex flex-col gap-6">
      <Section title="클라이언트 자격 증명">
        <SettingRow title="클라이언트 ID" description="앱이 이 시스템에 자신을 알리는 값입니다.">
          <CopyField label="클라이언트 ID" value={client.clientId} />
        </SettingRow>
        <SettingRow
          title="클라이언트 비밀키"
          description={client.confidential ? '서버가 토큰을 받을 때 쓰는 키입니다. 저장된 값은 다시 볼 수 없습니다.' : undefined}
        >
          {client.confidential ? (
            <div>
              <Button variant="outline" size="sm" onClick={() => setConfirmRotate(true)}>
                <RefreshCwIcon data-icon="inline-start" />
                새로 발급
              </Button>
            </div>
          ) : (
            <span className="text-sm text-muted-foreground">공개 클라이언트라서 비밀키가 없습니다. PKCE로 보호합니다.</span>
          )}
        </SettingRow>
      </Section>

      <Section title="클라이언트 설정">
        <SettingRow title="앱 유형">
          <div className="flex items-center gap-2">
            <Badge variant="outline">{CLIENT_TYPE_LABELS[client.applicationType]}</Badge>
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              <PencilIcon data-icon="inline-start" />
              편집
            </Button>
          </div>
        </SettingRow>
        <SettingRow title="부여 방식">
          <div className="flex flex-wrap gap-1.5">
            {client.grants.map((grant) => (
              <Badge key={grant} variant="secondary">
                {GRANT_LABELS[grant].label}
              </Badge>
            ))}
          </div>
        </SettingRow>
        <SettingRow title="토큰 보호">
          <div className="flex flex-wrap gap-1.5">
            {client.applicationType !== 'service' ? <Badge variant="secondary">PKCE {client.requirePkce ? '필수' : '선택'}</Badge> : null}
            <Badge variant="secondary">DPoP {client.dpop ? '필수' : '사용 안 함'}</Badge>
          </div>
        </SettingRow>
        {client.applicationType === 'service' ? (
          <SettingRow title="범위">
            <ValueList values={client.scopes} />
          </SettingRow>
        ) : (
          <>
            <SettingRow title="로그인 리다이렉트 주소">
              <ValueList values={client.redirectUris} />
            </SettingRow>
            <SettingRow title="로그아웃 리다이렉트 주소">
              <ValueList values={client.postLogoutRedirectUris} />
            </SettingRow>
            <SettingRow title="받을 수 있는 정보">
              <div className="flex flex-wrap gap-1.5">
                {client.scopes.map((scope) => (
                  <Badge key={scope} variant="secondary">
                    {SCOPE_LABELS[scope] ?? scope}
                  </Badge>
                ))}
              </div>
            </SettingRow>
          </>
        )}
      </Section>

      <Section title="앱에 알려 줄 주소">
        {discovery.isPending ? (
          <div className="py-6">
            <Skeleton className="h-24 rounded-lg" />
          </div>
        ) : (
          endpoints
            .filter(([, value]) => value)
            .map(([label, value]) => (
              <SettingRow key={label} title={label}>
                <CopyField label={label} value={value!} />
              </SettingRow>
            ))
        )}
        <SettingRow title="디스커버리 문서" description="대부분의 라이브러리는 이 주소 하나로 위 값을 자동으로 읽습니다.">
          <CopyField label="디스커버리 문서" value={`${window.location.origin}/.well-known/openid-configuration`} />
        </SettingRow>
      </Section>

      <OidcEditDialog
        open={editing}
        onOpenChange={setEditing}
        slug={slug}
        client={client}
        onSaved={() => queryClient.invalidateQueries({ queryKey: integrationKey(slug) })}
      />

      <AlertDialog open={confirmRotate} onOpenChange={(open) => !rotate.isPending && setConfirmRotate(open)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>비밀키를 새로 발급할까요?</AlertDialogTitle>
            <AlertDialogDescription>이전 비밀키는 바로 쓸 수 없게 됩니다. 앱에 새 키를 넣을 때까지 이 앱의 토큰 요청이 실패합니다.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={rotate.isPending}>취소</AlertDialogCancel>
            <AlertDialogAction
              disabled={rotate.isPending}
              onClick={(event) => {
                event.preventDefault()
                rotate.mutate()
              }}
            >
              {rotate.isPending ? <Spinner data-icon="inline-start" /> : null}
              새로 발급
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <SecretDialog created={rotated ? { clientId: client.clientId, secret: rotated } : null} onClose={() => setRotated(null)} />
    </div>
  )
}

function OidcEditDialog({
  open,
  onOpenChange,
  slug,
  client,
  onSaved,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  slug: string
  client: OidcClient
  onSaved: () => unknown
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-3xl">
        {open ? <OidcEditForm key={client.clientId} slug={slug} client={client} onClose={() => onOpenChange(false)} onSaved={onSaved} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function OidcEditForm({
  client,
  onClose,
  onSaved,
}: {
  slug: string
  client: OidcClient
  onClose: () => void
  onSaved: () => unknown
}) {
  const [draft, setDraft] = useState<OidcDraft>(() => draftFromClient(client))
  const [failure, setFailure] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () =>
      apiFetch(`/api/admin/oidc-clients/${client.clientId}`, {
        method: 'PATCH',
        body: JSON.stringify(oidcBody(client.applicationType, draft)),
      }),
    onSuccess: async () => {
      toast.success('클라이언트 설정을 저장했습니다.')
      await onSaved()
      onClose()
    },
    onError: (cause: unknown) => setFailure(explain(cause, '저장하지 못했습니다.')),
  })
  return (
    <>
      <DialogHeader>
        <DialogTitle>클라이언트 설정 편집</DialogTitle>
        <DialogDescription>{CLIENT_TYPE_LABELS[client.applicationType]}의 유형은 바꿀 수 없습니다.</DialogDescription>
      </DialogHeader>
      <div className="divide-y">
        <OidcFields type={client.applicationType} draft={draft} onChange={setDraft} />
      </div>
      {failure ? (
        <Alert variant="destructive">
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      ) : null}
      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={save.isPending}>
          취소
        </Button>
        <Button
          disabled={save.isPending}
          onClick={() => {
            const problem = oidcDraftProblem(client.applicationType, draft)
            if (problem) setFailure(problem)
            else {
              setFailure(null)
              save.mutate()
            }
          }}
        >
          {save.isPending ? <Spinner data-icon="inline-start" /> : null}
          저장
        </Button>
      </DialogFooter>
    </>
  )
}

function SamlPanel({ slug, data }: { slug: string; data: Integration }) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const saml = data.saml
  const endpoints = data.endpoints ?? {}
  return (
    <div className="flex flex-col gap-6">
      <Section title="이 시스템의 정보 (앱에 입력)">
        <SettingRow title="메타데이터 주소" description="앱이 지원하면 이 주소 하나로 아래 값을 모두 읽습니다.">
          <CopyField label="메타데이터 주소" value={endpoints.metadata ?? ''} />
          <div>
            <Button asChild variant="outline" size="sm">
              <a href={endpoints.metadata} target="_blank" rel="noreferrer">
                <ExternalLinkIcon data-icon="inline-start" />
                메타데이터 열기
              </a>
            </Button>
          </div>
        </SettingRow>
        <SettingRow title="로그인 주소 (SSO)">
          <CopyField label="로그인 주소" value={endpoints.sso ?? ''} />
        </SettingRow>
      </Section>
      <Section title="앱의 정보">
        {saml ? (
          <>
            <SettingRow title="엔티티 ID">
              <CopyField label="엔티티 ID" value={saml.entityId} />
            </SettingRow>
            <SettingRow title="ACS 주소">
              <CopyField label="ACS 주소" value={saml.acsUrl} />
            </SettingRow>
            <SettingRow title="서명 인증서">
              <Textarea aria-label="서명 인증서" readOnly rows={4} className="font-mono text-xs md:text-xs" value={saml.signingCertificate} />
              <div>
                <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                  <PencilIcon data-icon="inline-start" />
                  편집
                </Button>
              </div>
            </SettingRow>
          </>
        ) : (
          <SettingRow title="서비스 제공자">
            <span className="text-sm text-muted-foreground">등록 정보를 찾을 수 없습니다.</span>
          </SettingRow>
        )}
      </Section>
      {saml ? (
        <ProviderEditDialog
          open={editing}
          onOpenChange={setEditing}
          slug={slug}
          title="SAML 설정 편집"
          fields={[
            { key: 'acsUrl', label: 'ACS 주소', value: saml.acsUrl },
            { key: 'signingCertificate', label: '서명 인증서', value: saml.signingCertificate, multiline: true },
          ]}
          onSaved={() => queryClient.invalidateQueries({ queryKey: integrationKey(slug) })}
        />
      ) : null}
    </div>
  )
}

function WsfedPanel({ slug, data }: { slug: string; data: Integration }) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const party = data.wsfed
  const endpoints = data.endpoints ?? {}
  return (
    <div className="flex flex-col gap-6">
      <Section title="이 시스템의 정보 (앱에 입력)">
        <SettingRow title="메타데이터 주소">
          <CopyField label="메타데이터 주소" value={endpoints.metadata ?? ''} />
        </SettingRow>
        <SettingRow title="로그인 주소">
          <CopyField label="로그인 주소" value={endpoints.signin ?? ''} />
        </SettingRow>
      </Section>
      <Section title="앱의 정보">
        {party ? (
          <>
            <SettingRow title="Realm">
              <CopyField label="Realm" value={party.realm} />
            </SettingRow>
            <SettingRow title="회신 주소">
              <CopyField label="회신 주소" value={party.replyUrl} />
              <div>
                <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                  <PencilIcon data-icon="inline-start" />
                  편집
                </Button>
              </div>
            </SettingRow>
          </>
        ) : (
          <SettingRow title="신뢰 당사자">
            <span className="text-sm text-muted-foreground">등록 정보를 찾을 수 없습니다.</span>
          </SettingRow>
        )}
      </Section>
      {party ? (
        <ProviderEditDialog
          open={editing}
          onOpenChange={setEditing}
          slug={slug}
          title="WS-Fed 설정 편집"
          fields={[{ key: 'replyUrl', label: '회신 주소', value: party.replyUrl }]}
          onSaved={() => queryClient.invalidateQueries({ queryKey: integrationKey(slug) })}
        />
      ) : null}
    </div>
  )
}

type EditableField = { key: string; label: string; value: string; multiline?: boolean }

function ProviderEditDialog({
  open,
  onOpenChange,
  slug,
  title,
  fields,
  onSaved,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  slug: string
  title: string
  fields: EditableField[]
  onSaved: () => unknown
}) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((field) => [field.key, field.value])))
  const [failure, setFailure] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => apiFetch(`/api/admin/applications/${slug}/integration`, { method: 'PUT', body: JSON.stringify(values) }),
    onSuccess: async () => {
      toast.success('저장했습니다.')
      await onSaved()
      onOpenChange(false)
    },
    onError: (cause: unknown) => setFailure(explain(cause, '저장하지 못했습니다.')),
  })
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) {
          setValues(Object.fromEntries(fields.map((field) => [field.key, field.value])))
          setFailure(null)
        }
        if (!save.isPending) onOpenChange(next)
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>식별 값(엔티티 ID, Realm)은 바꿀 수 없습니다. 바꾸려면 앱을 새로 만드세요.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {fields.map((field) => (
            <div key={field.key} className="flex flex-col gap-1.5">
              <label htmlFor={`edit-${field.key}`} className="text-sm font-medium">
                {field.label}
              </label>
              {field.multiline ? (
                <Textarea id={`edit-${field.key}`} rows={6} spellCheck={false} className="font-mono text-xs" value={values[field.key] ?? ''} onChange={(event) => setValues({ ...values, [field.key]: event.target.value })} />
              ) : (
                <Input id={`edit-${field.key}`} autoComplete="off" spellCheck={false} value={values[field.key] ?? ''} onChange={(event) => setValues({ ...values, [field.key]: event.target.value })} />
              )}
            </div>
          ))}
        </div>
        {failure ? (
          <Alert variant="destructive">
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={save.isPending}>
            취소
          </Button>
          <Button disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
