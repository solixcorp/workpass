import { CircleAlertIcon, LockIcon, RefreshCwIcon, ShieldCheckIcon, WorkflowIcon } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, FieldContent, FieldDescription, FieldLabel } from '@/components/ui/field'
import { Switch } from '@/components/ui/switch'
import type { Method } from '@/lib/integrations'
import { Form } from './new-integration-page'

/** A capability an app integration can have: on or off, with choices inside. */
function Capability({
  title,
  description,
  checked,
  onChange,
  locked,
  note,
  children,
}: {
  title: string
  description: string
  checked?: boolean
  onChange?: (on: boolean) => void
  locked?: string
  note?: ReactNode
  children?: ReactNode
}) {
  return (
    <div className={`flex flex-col gap-4 rounded-2xl border bg-card p-6 ${locked ? 'bg-muted/40' : ''}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h3 className={`text-sm font-semibold ${locked ? 'text-muted-foreground' : ''}`}>{title}</h3>
          <p className="text-xs text-muted-foreground">{description}</p>
          {locked ? (
            <p className="flex items-center gap-1.5 pt-1 text-xs text-muted-foreground">
              <CircleAlertIcon className="size-3.5 shrink-0" />
              {locked}
            </p>
          ) : null}
          {note}
        </div>
        {locked ? (
          <LockIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        ) : (
          <Switch aria-label={title} checked={checked} onCheckedChange={onChange} />
        )}
      </div>
      {checked && children ? <div className="flex flex-col gap-4 border-t pt-4">{children}</div> : null}
    </div>
  )
}

function Choice({
  id,
  title,
  description,
  checked,
  onChange,
}: {
  id: string
  title: string
  description: string
  checked: boolean
  onChange: (on: boolean) => void
}) {
  return (
    <Field orientation="horizontal">
      <Checkbox id={id} checked={checked} onCheckedChange={(on) => onChange(on === true)} />
      <FieldContent>
        <FieldLabel htmlFor={id}>{title}</FieldLabel>
        <FieldDescription>{description}</FieldDescription>
      </FieldContent>
    </Field>
  )
}

/**
 * The integration wizard: turn on what the app needs, then fill in its details.
 * An app has one sign-in protocol, so single sign-on takes OIDC or SAML, and an
 * API service is its own integration. Capabilities this system does not have are
 * shown locked, with the reason.
 */
export function IntegrationWizardPage() {
  const [sso, setSso] = useState(false)
  const [ssoKind, setSsoKind] = useState<'oidc' | 'saml'>('oidc')
  const [api, setApi] = useState(false)

  const method: Method | null = api ? 'api' : sso ? ssoKind : null

  const header = (
    <>
      <div className="rounded-2xl border bg-card p-6">
        <h2 className="text-base font-semibold">제목 없는 통합</h2>
        <p className="pt-1 text-xs text-muted-foreground">
          마지막 수정: <b>없음</b>
        </p>
      </div>
      <div className="flex flex-col gap-3">
        <h2 className="text-base font-semibold">통합 기능 추가</h2>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-2 text-sm font-medium">
              <ShieldCheckIcon className="size-4" />
              세션 수명 주기 관리
            </div>
            <Capability
              title="SSO (싱글 사인온)"
              description="사용자가 이 시스템으로 앱에 로그인하게 합니다."
              checked={sso}
              onChange={(on) => {
                setSso(on)
                if (on) setApi(false)
              }}
            >
              <Choice
                id="wizard-oidc"
                title="OpenID Connect (OIDC)"
                description="OAuth 2.0 위에서 로그인합니다. 새로 연동하는 앱, 모바일·클라우드 앱에 권장합니다."
                checked={ssoKind === 'oidc'}
                onChange={(on) => on && setSsoKind('oidc')}
              />
              <Choice
                id="wizard-saml"
                title="SAML 2.0"
                description="브라우저가 중개하는 표준 로그인입니다. OIDC를 쓸 수 없을 때 씁니다."
                checked={ssoKind === 'saml'}
                onChange={(on) => on && setSsoKind('saml')}
              />
              <p className="text-xs text-muted-foreground">한 앱은 로그인 방식 하나를 씁니다. 둘 다 필요하면 앱을 따로 만드세요.</p>
            </Capability>
            <Capability
              title="유니버설 로그아웃"
              description="위험이 바뀌면 사용자의 세션과 토큰을 앱에서도 끊습니다."
              locked="이 시스템은 앱의 세션을 대신 끊을 수 없습니다. 지금은 이 시스템의 세션과 토큰만 끊깁니다."
            />
          </div>
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-2 text-sm font-medium">
              <WorkflowIcon className="size-4" />
              ID 수명 주기 관리
            </div>
            <Capability
              title="프로비저닝"
              description="이 시스템과 앱의 사용자 계정을 동기화합니다."
              locked="SCIM 전달은 배포 전체에 대상 하나만 설정할 수 있어서, 앱마다 켤 수 없습니다."
            />
            <Capability
              title="권한(엔타이틀먼트) 관리"
              description="앱의 권한 수준을 여러 앱에 걸쳐 관리합니다."
              locked="아직 없는 기능입니다."
            />
          </div>
        </div>
        <div className="flex flex-col gap-4 pt-2">
          <div className="flex items-center gap-2 text-sm font-medium">
            <RefreshCwIcon className="size-4" />
            기타 연동
          </div>
          <div className="max-w-xl">
            <Capability
              title="API 서비스"
              description="사용자 없이 서버끼리 범위가 정해진 OAuth 2.0 토큰으로 API를 호출합니다."
              checked={api}
              onChange={(on) => {
                setApi(on)
                if (on) setSso(false)
              }}
              note={<span className="pt-1 text-xs text-muted-foreground">켜면 SSO는 꺼집니다.</span>}
            />
          </div>
        </div>
      </div>
      {method ? <h2 className="text-base font-semibold">통합 세부 정보</h2> : null}
    </>
  )

  if (!method) {
    return (
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-6">
        <h1 className="text-xl font-semibold">통합 마법사</h1>
        {header}
        <p className="text-sm text-muted-foreground">위에서 통합 기능을 하나 켜면 세부 정보와 설정 항목이 나옵니다.</p>
      </div>
    )
  }
  return <Form key={method} method={method} type="web" wizard header={header} />
}
