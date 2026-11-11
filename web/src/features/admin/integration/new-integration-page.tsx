import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { ArrowLeftIcon, ImageIcon, UploadIcon } from 'lucide-react'
import { useRef, useState, type FormEvent, type ReactNode } from 'react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { FieldDescription } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { Field, FieldContent, FieldLabel } from '@/components/ui/field'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Textarea } from '@/components/ui/textarea'
import { ApiError, apiFetch } from '@/lib/api'
import {
  CLIENT_TYPES,
  CLIENT_TYPE_LABELS,
  groupsQuery,
  parseClientType,
  parseMethod,
  slugify,
  type ClientType,
  type Method,
} from '@/lib/integrations'
import {
  defaultOidcDraft,
  OidcFields,
  oidcBody,
  oidcDraftProblem,
  type OidcDraft,
} from './oidc-fields'
import { AssignmentChooser, CopyField, Section, SettingRow, type AssignChoice } from './parts'

const SLUG = /^[a-z0-9][a-z0-9-]{0,63}$/

function title(method: Method, type: Exclude<ClientType, 'service'>): string {
  switch (method) {
    case 'oidc':
      return `새 ${CLIENT_TYPE_LABELS[type]} 연동`
    case 'saml':
      return '새 SAML 2.0 앱 연동'
    case 'wsfed':
      return '새 WS-Federation 앱 연동'
    case 'swa':
      return '새 SWA 앱 연동'
    case 'api':
      return '새 API 서비스 연동'
    default:
      return '새 북마크 앱'
  }
}

function explain(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (/[가-힣]/.test(error.message)) return error.message
    if (error.status === 409) return '같은 값으로 등록된 항목이 이미 있습니다.'
  }
  return fallback
}

/** The settings form for a new app of the chosen sign-in method. */
export function NewIntegrationPage() {
  const search = useSearch({ strict: false }) as { method?: string; type?: string }
  const method = parseMethod(search.method)
  const type = parseClientType(search.type)
  if (!method) {
    return (
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
        <Alert>
          <AlertDescription>로그인 방식을 먼저 고르세요.</AlertDescription>
        </Alert>
        <div>
          <Button asChild variant="outline">
            <Link to="/admin/applications">앱 목록으로</Link>
          </Button>
        </div>
      </div>
    )
  }
  return <Form key={`${method}-${type}`} method={method} type={type} />
}

/** The settings form. In the wizard the capability cards above it decide the method; the form adds the app type, description and logo. */
export function Form({
  method,
  type: initialType,
  wizard = false,
  header,
}: {
  method: Method
  type: Exclude<ClientType, 'service'>
  wizard?: boolean
  header?: ReactNode
}) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [type, setType] = useState(initialType)
  const clientType: ClientType = method === 'api' ? 'service' : type
  const logoInput = useRef<HTMLInputElement>(null)
  const [logo, setLogo] = useState<File | null>(null)
  const [description, setDescription] = useState('')
  const groups = useQuery(groupsQuery)

  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [launchUrl, setLaunchUrl] = useState('')
  const [oidc, setOidc] = useState<OidcDraft>(() => defaultOidcDraft(clientType))
  const [saml, setSaml] = useState({ entityId: '', acsUrl: '', certificate: '' })
  const [wsfed, setWsfed] = useState({ realm: '', replyUrl: '' })
  const [swaOrigin, setSwaOrigin] = useState('')
  const [choice, setChoice] = useState<AssignChoice>('everyone')
  const [selected, setSelected] = useState<string[]>([])
  const [pending, setPending] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [created, setCreated] = useState<{ slug: string; clientId: string; secret: string | null } | null>(null)

  const usesOidc = method === 'oidc' || method === 'api'
  const showLaunch = method !== 'api'

  function validate(): string | null {
    if (!name.trim() || name.trim().length > 128) return '앱 이름은 1자에서 128자 사이여야 합니다.'
    if (!SLUG.test(slug)) return '식별자는 영문 소문자, 숫자, 하이픈만 쓸 수 있고 글자나 숫자로 시작해야 합니다.'
    if (usesOidc) return oidcDraftProblem(clientType, oidc)
    if (method === 'saml') {
      if (!saml.entityId.trim()) return '서비스 제공자의 엔티티 ID를 넣으세요.'
      if (!saml.acsUrl.trim()) return 'ACS(어서션 소비자) 주소를 넣으세요.'
      if (!saml.certificate.trim()) return '서명 인증서(PEM)를 넣으세요.'
    }
    if (method === 'wsfed' && (!wsfed.realm.trim() || !wsfed.replyUrl.trim())) return 'Realm과 회신 주소를 넣으세요.'
    if (method === 'swa' && !swaOrigin.trim()) return '로그인 화면이 있는 사이트 주소(origin)를 넣으세요.'
    if (method === 'bookmark' && !launchUrl.trim()) return '열 주소를 넣으세요.'
    if (choice === 'groups' && selected.length === 0) return '허용할 그룹을 하나 이상 고르세요.'
    return null
  }

  async function createProvider(): Promise<{ binding: string | null; rollback: () => Promise<unknown>; secret: string | null; clientId: string }> {
    if (usesOidc) {
      const result = await apiFetch<{ client: { clientId: string }; clientSecret: string | null }>('/api/admin/oidc-clients', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim(), applicationType: clientType, ...oidcBody(clientType, oidc) }),
      })
      const id = result.client.clientId
      return {
        binding: id,
        clientId: id,
        secret: result.clientSecret,
        rollback: () => apiFetch(`/api/admin/oidc-clients/${id}`, { method: 'DELETE' }),
      }
    }
    if (method === 'saml') {
      const result = await apiFetch<{ provider: { id: string; entityId: string } }>('/api/admin/saml-service-providers', {
        method: 'POST',
        body: JSON.stringify({ entityId: saml.entityId.trim(), acsUrl: saml.acsUrl.trim(), signingCertificate: saml.certificate.trim(), verifyCertificate: true }),
      })
      return {
        binding: result.provider.entityId,
        clientId: '',
        secret: null,
        rollback: () => apiFetch(`/api/admin/saml-service-providers/${result.provider.id}`, { method: 'DELETE' }),
      }
    }
    if (method === 'wsfed') {
      const result = await apiFetch<{ party: { id: string; realm: string } }>('/api/admin/wsfed-relying-parties', {
        method: 'POST',
        body: JSON.stringify({ realm: wsfed.realm.trim(), replyUrl: wsfed.replyUrl.trim() }),
      })
      return {
        binding: result.party.realm,
        clientId: '',
        secret: null,
        rollback: () => apiFetch(`/api/admin/wsfed-relying-parties/${result.party.id}`, { method: 'DELETE' }),
      }
    }
    if (method === 'swa') {
      const result = await apiFetch<{ application: { id: string; origin: string } }>('/api/admin/swa-applications', {
        method: 'POST',
        // The registry keeps a plain identifier here; the display name lives on the app.
        body: JSON.stringify({ name: slug, origin: swaOrigin.trim() }),
      })
      return {
        binding: result.application.origin,
        clientId: '',
        secret: null,
        rollback: () => apiFetch(`/api/admin/swa-applications/${result.application.id}`, { method: 'DELETE' }),
      }
    }
    return { binding: null, clientId: '', secret: null, rollback: async () => undefined }
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setFailure(null)
    const problem = validate()
    if (problem) {
      setFailure(problem)
      return
    }
    setPending(true)
    let provider: Awaited<ReturnType<typeof createProvider>>
    try {
      provider = await createProvider()
    } catch (error) {
      setPending(false)
      setFailure(explain(error, '연동 정보를 만들지 못했습니다. 입력한 주소와 값을 확인하세요.'))
      return
    }
    try {
      await apiFetch('/api/admin/applications', {
        method: 'POST',
        body: JSON.stringify({
          slug,
          name: name.trim(),
          ...(description.trim() ? { description: description.trim() } : {}),
          protocol: method === 'api' ? 'oidc' : method,
          ...(provider.binding ? { binding: provider.binding } : {}),
          ...(launchUrl.trim() && showLaunch ? { launchUrl: launchUrl.trim() } : {}),
          ...(method === 'api' ? { hideFromDashboard: true } : {}),
        }),
      })
    } catch (error) {
      // Nothing may be left behind that no app points at.
      await provider.rollback().catch(() => undefined)
      setPending(false)
      setFailure(
        error instanceof ApiError && error.status === 409
          ? '같은 식별자의 앱이 이미 있습니다. 식별자를 바꾸세요.'
          : explain(error, '앱을 만들지 못했습니다.'),
      )
      return
    }

    if (logo) {
      const form = new FormData()
      form.set('file', logo)
      const uploaded = await fetch(`/api/admin/applications/${slug}/icon`, { method: 'POST', body: form, credentials: 'same-origin' }).catch(() => null)
      if (!uploaded?.ok) toast.warning('앱은 만들었지만 로고를 올리지 못했습니다. 상세 화면에서 다시 올려 보세요.')
    }

    let enabled = false
    if (choice !== 'later') {
      try {
        if (choice === 'groups') {
          await apiFetch(`/api/admin/applications/${slug}/assignment`, {
            method: 'PUT',
            body: JSON.stringify({ mode: 'groups', groups: selected }),
          })
        }
        await apiFetch(`/api/admin/applications/${slug}/enable`, { method: 'POST' })
        enabled = true
      } catch (error) {
        toast.warning(`앱은 만들었지만 켜지 못했습니다. ${explain(error, '상세 화면에서 다시 켜 보세요.')}`)
      }
    }
    await queryClient.invalidateQueries({ queryKey: ['admin', 'applications'] })
    setPending(false)
    toast.success(enabled ? '앱을 만들고 켰습니다.' : '앱을 만들었습니다.')
    if (provider.secret) setCreated({ slug, clientId: provider.clientId, secret: provider.secret })
    else void navigate({ to: '/admin/applications/$slug', params: { slug } })
  }

  const onName = (value: string) => {
    setName(value)
    if (!slugTouched) setSlug(slugify(value))
  }

  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6">
      <div className="flex flex-col gap-3">
        <Button asChild variant="ghost" size="sm" className="self-start">
          <Link to="/admin/applications">
            <ArrowLeftIcon data-icon="inline-start" />앱 목록
          </Link>
        </Button>
        <h1 className="text-xl font-semibold">{wizard ? '통합 마법사' : title(method, type)}</h1>
      </div>
      {header}

      <form onSubmit={submit} noValidate className="flex flex-col gap-6">
        <Section title="일반 설정">
          <SettingRow title="앱 이름" description="포털과 관리 화면에 보이는 이름입니다.">
            <Input id="new-app-name" aria-label="앱 이름" autoComplete="off" maxLength={128} placeholder="내 웹 앱" value={name} onChange={(event) => onName(event.target.value)} />
          </SettingRow>
          <SettingRow title="식별자" description="주소와 설정에 쓰이는 이름입니다. 만든 뒤에는 바꿀 수 없습니다.">
            <Input
              id="new-app-slug"
              aria-label="식별자"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              className="font-mono"
              maxLength={64}
              placeholder="my-web-app"
              value={slug}
              onChange={(event) => {
                setSlugTouched(true)
                setSlug(event.target.value)
              }}
            />
          </SettingRow>
          <SettingRow title="설명" description="포털 앱 카드에 보입니다. 선택 사항입니다.">
            <Textarea id="new-app-description" aria-label="설명" rows={2} maxLength={512} value={description} onChange={(event) => setDescription(event.target.value)} />
          </SettingRow>
          {method !== 'api' ? (
            <SettingRow title="로고" description="PNG, JPEG, WebP, GIF, SVG, 1MB 이하입니다. 선택 사항입니다.">
              <div className="flex items-center gap-3">
                <div className="flex size-12 shrink-0 items-center justify-center overflow-hidden rounded-xl border bg-card">
                  {logo ? <img src={URL.createObjectURL(logo)} alt="" className="size-full object-contain p-1" /> : <ImageIcon className="text-muted-foreground" />}
                </div>
                <input
                  ref={logoInput}
                  type="file"
                  hidden
                  accept="image/png,image/jpeg,image/webp,image/gif,image/svg+xml"
                  aria-label="로고 파일"
                  onChange={(event) => {
                    const file = event.target.files?.[0] ?? null
                    event.target.value = ''
                    if (file && file.size > 1024 * 1024) setFailure('로고는 1MB 이하여야 합니다.')
                    else setLogo(file)
                  }}
                />
                <Button type="button" variant="outline" size="sm" onClick={() => logoInput.current?.click()}>
                  <UploadIcon data-icon="inline-start" />
                  {logo ? '다른 이미지 고르기' : '이미지 고르기'}
                </Button>
                {logo ? (
                  <Button type="button" variant="ghost" size="sm" onClick={() => setLogo(null)}>
                    지우기
                  </Button>
                ) : null}
              </div>
            </SettingRow>
          ) : null}
          {showLaunch ? (
            <SettingRow
              title="실행 주소"
              description={method === 'bookmark' ? '포털에서 이 앱을 누르면 열리는 주소입니다.' : '포털에서 이 앱을 누르면 열리는 주소입니다. 선택 사항입니다.'}
            >
              <Input id="new-app-launch" aria-label="실행 주소" type="url" autoComplete="off" spellCheck={false} placeholder="https://" value={launchUrl} onChange={(event) => setLaunchUrl(event.target.value)} />
            </SettingRow>
          ) : null}
        </Section>

        {usesOidc ? (
          <Section title="클라이언트 설정">
            {wizard && method === 'oidc' ? (
              <SettingRow title="앱 유형" description="유형에 맞게 설정 항목이 정해집니다.">
                <RadioGroup
                  value={type}
                  onValueChange={(value) => {
                    setType(value as typeof type)
                    setOidc(defaultOidcDraft(value as ClientType))
                  }}
                >
                  {CLIENT_TYPES.map((entry) => (
                    <Field key={entry.value} orientation="horizontal">
                      <RadioGroupItem id={`wizard-type-${entry.value}`} value={entry.value} />
                      <FieldContent>
                        <FieldLabel htmlFor={`wizard-type-${entry.value}`}>{entry.label}</FieldLabel>
                        <FieldDescription>{entry.description}</FieldDescription>
                      </FieldContent>
                    </Field>
                  ))}
                </RadioGroup>
              </SettingRow>
            ) : null}
            <OidcFields type={clientType} draft={oidc} onChange={setOidc} />
          </Section>
        ) : null}

        {method === 'saml' ? (
          <Section title="SAML 설정">
            <SettingRow title="엔티티 ID" description="서비스 제공자(앱)가 자신을 부르는 이름입니다.">
              <Input id="saml-entity" aria-label="엔티티 ID" autoComplete="off" spellCheck={false} placeholder="https://app.example.com/saml/metadata" value={saml.entityId} onChange={(event) => setSaml({ ...saml, entityId: event.target.value })} />
            </SettingRow>
            <SettingRow title="ACS 주소" description="로그인 결과(어서션)를 받는 주소입니다. https여야 합니다.">
              <Input id="saml-acs" aria-label="ACS 주소" autoComplete="off" spellCheck={false} placeholder="https://app.example.com/saml/acs" value={saml.acsUrl} onChange={(event) => setSaml({ ...saml, acsUrl: event.target.value })} />
            </SettingRow>
            <SettingRow title="서명 인증서" description="앱이 로그인 요청에 서명할 때 쓰는 RSA 인증서(PEM)입니다.">
              <Textarea id="saml-cert" aria-label="서명 인증서" rows={6} spellCheck={false} className="font-mono text-xs md:text-xs" placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'} value={saml.certificate} onChange={(event) => setSaml({ ...saml, certificate: event.target.value })} />
              <FieldDescription>이 시스템의 메타데이터 주소와 로그인 주소는 앱을 만든 뒤 상세 화면에 나옵니다.</FieldDescription>
            </SettingRow>
          </Section>
        ) : null}

        {method === 'wsfed' ? (
          <Section title="WS-Federation 설정">
            <SettingRow title="Realm" description="앱이 자신을 부르는 식별 값(wtrealm)입니다.">
              <Input id="wsfed-realm" aria-label="Realm" autoComplete="off" spellCheck={false} placeholder="urn:corp:app" value={wsfed.realm} onChange={(event) => setWsfed({ ...wsfed, realm: event.target.value })} />
            </SettingRow>
            <SettingRow title="회신 주소" description="로그인 결과 토큰을 돌려보낼 주소입니다. https여야 합니다.">
              <Input id="wsfed-reply" aria-label="회신 주소" autoComplete="off" spellCheck={false} placeholder="https://app.example.com/wsfed" value={wsfed.replyUrl} onChange={(event) => setWsfed({ ...wsfed, replyUrl: event.target.value })} />
            </SettingRow>
          </Section>
        ) : null}

        {method === 'swa' ? (
          <Section title="SWA 설정">
            <SettingRow title="사이트 주소" description="로그인 화면이 있는 사이트의 origin입니다. 이 사이트에서만 자동 로그인이 동작합니다.">
              <Input id="swa-origin" aria-label="사이트 주소" autoComplete="off" spellCheck={false} placeholder="https://legacy.example.com" value={swaOrigin} onChange={(event) => setSwaOrigin(event.target.value)} />
            </SettingRow>
          </Section>
        ) : null}

        {method !== 'api' ? (
          <Section title="할당">
            <SettingRow title="접근 허용 대상" description="이 앱을 열 수 있는 사람입니다. 만든 뒤 상세 화면에서 바꿀 수 있습니다.">
              <AssignmentChooser
                choice={choice}
                onChoice={setChoice}
                groups={groups.data}
                loading={groups.isPending}
                selected={selected}
                onSelected={setSelected}
                allowLater
              />
            </SettingRow>
          </Section>
        ) : (
          <Alert>
            <AlertDescription>API 서비스 앱은 사용자에게 보이지 않습니다. 만든 뒤 바로 켜지고, 비밀키를 한 번 보여 드립니다.</AlertDescription>
          </Alert>
        )}

        {failure ? (
          <Alert variant="destructive">
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        ) : null}
        <div className="flex items-center gap-2">
          <Button type="submit" disabled={pending}>
            {pending ? <Spinner data-icon="inline-start" /> : null}
            저장
          </Button>
          <Button asChild type="button" variant="ghost">
            <Link to="/admin/applications">취소</Link>
          </Button>
        </div>
      </form>

      <SecretDialog
        created={created}
        onClose={() => {
          const slugDone = created?.slug
          setCreated(null)
          if (slugDone) void navigate({ to: '/admin/applications/$slug', params: { slug: slugDone } })
        }}
      />
    </div>
  )
}

/** The client secret, shown once. */
export function SecretDialog({
  created,
  onClose,
}: {
  created: { clientId: string; secret: string | null } | null
  onClose: () => void
}) {
  return (
    <Dialog open={created !== null && created.secret !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>클라이언트 비밀키를 저장하세요</DialogTitle>
          <DialogDescription>이 키는 지금만 볼 수 있습니다. 닫으면 다시 볼 수 없고, 잃어버리면 새로 발급해야 합니다.</DialogDescription>
        </DialogHeader>
        {created ? (
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium">클라이언트 ID</span>
              <CopyField label="클라이언트 ID" value={created.clientId} />
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-sm font-medium">클라이언트 비밀키</span>
              <CopyField label="클라이언트 비밀키" value={created.secret ?? ''} />
            </div>
          </div>
        ) : null}
        <DialogFooter>
          <Button onClick={onClose}>저장했습니다</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
