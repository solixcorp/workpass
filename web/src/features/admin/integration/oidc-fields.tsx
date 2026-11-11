import { Checkbox } from '@/components/ui/checkbox'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import type { ClientType, GrantKey, OidcClient } from '@/lib/integrations'
import { GrantsField, SettingRow, UriListField } from './parts'

export type OidcDraft = {
  grants: GrantKey[]
  redirectUris: string[]
  postLogoutRedirectUris: string[]
  scopes: string[]
  requirePkce: boolean
  dpop: boolean
}

const USER_SCOPES: Array<{ key: string; label: string; description: string }> = [
  { key: 'profile', label: '프로필', description: '이름과 사용자 이름' },
  { key: 'email', label: '이메일', description: '이메일 주소와 확인 여부' },
  { key: 'phone', label: '전화번호', description: '등록된 전화번호' },
  { key: 'groups', label: '그룹', description: '소속 그룹 이름' },
]

export function defaultOidcDraft(type: ClientType): OidcDraft {
  return {
    grants: type === 'service' ? ['client_credentials'] : ['authorization_code'],
    redirectUris: [''],
    postLogoutRedirectUris: [],
    scopes: type === 'service' ? [''] : ['profile', 'email'],
    requirePkce: true,
    dpop: false,
  }
}

export function draftFromClient(client: OidcClient): OidcDraft {
  const user = client.applicationType !== 'service'
  return {
    grants: client.grants,
    redirectUris: client.redirectUris.length ? client.redirectUris : [''],
    postLogoutRedirectUris: client.postLogoutRedirectUris,
    scopes: user ? client.scopes.filter((scope) => scope !== 'openid' && scope !== 'offline_access') : client.scopes.length ? client.scopes : [''],
    requirePkce: client.requirePkce,
    dpop: client.dpop,
  }
}

/** The request body for the server, with blank rows dropped. */
export function oidcBody(type: ClientType, draft: OidcDraft) {
  const clean = (values: string[]) => values.map((value) => value.trim()).filter(Boolean)
  return {
    grants: draft.grants,
    redirectUris: type === 'service' ? [] : clean(draft.redirectUris),
    postLogoutRedirectUris: type === 'service' ? [] : clean(draft.postLogoutRedirectUris),
    scopes: clean(draft.scopes),
    requirePkce: draft.requirePkce,
    dpop: draft.dpop,
  }
}

export function oidcDraftProblem(type: ClientType, draft: OidcDraft): string | null {
  if (type !== 'service' && !draft.redirectUris.some((uri) => uri.trim())) return '로그인 리다이렉트 주소를 하나 이상 넣으세요.'
  if (type === 'service' && !draft.scopes.some((scope) => scope.trim())) return '이 앱이 받을 수 있는 범위를 하나 이상 넣으세요.'
  return null
}

/** The grant options each kind of app may use. */
function grantOptions(type: ClientType): { options: GrantKey[]; locked: GrantKey[] } {
  if (type === 'service') return { options: ['client_credentials'], locked: ['client_credentials'] }
  if (type === 'spa') return { options: ['authorization_code', 'refresh_token', 'device_code'], locked: ['authorization_code'] }
  return { options: ['authorization_code', 'refresh_token', 'device_code', 'ciba'], locked: ['authorization_code'] }
}

export function OidcFields({
  type,
  draft,
  onChange,
}: {
  type: ClientType
  draft: OidcDraft
  onChange: (draft: OidcDraft) => void
}) {
  const { options, locked } = grantOptions(type)
  const patch = (next: Partial<OidcDraft>) => onChange({ ...draft, ...next })
  const service = type === 'service'

  return (
    <>
      <SettingRow
        title="부여 방식"
        description={service ? '이 앱은 사용자 없이 자기 이름으로 토큰을 받습니다.' : '앱이 토큰을 받는 방법입니다.'}
      >
        <GrantsField options={options} locked={locked} value={draft.grants} onChange={(grants) => patch({ grants })} />
        {draft.grants.includes('device_code') || draft.grants.includes('ciba') ? (
          <p className="text-sm text-muted-foreground">
            기기 코드와 CIBA는 서버에서 해당 기능이 켜져 있어야 동작합니다.
          </p>
        ) : null}
      </SettingRow>

      <SettingRow title="토큰 보호" description="토큰이 유출돼도 다른 곳에서 쓰지 못하게 하는 설정입니다.">
        <FieldGroup className="gap-3">
          {service ? null : (
            <Field orientation="horizontal">
              <Checkbox
                id="oidc-pkce"
                checked={type === 'web' ? draft.requirePkce : true}
                disabled={type !== 'web'}
                onCheckedChange={(on) => patch({ requirePkce: on === true })}
              />
              <div className="flex flex-col gap-0.5">
                <FieldLabel htmlFor="oidc-pkce">PKCE 필수</FieldLabel>
                <FieldDescription>
                  {type === 'web' ? '코드를 가로채도 토큰을 받지 못하게 합니다.' : '이 유형의 앱은 항상 PKCE를 씁니다.'}
                </FieldDescription>
              </div>
            </Field>
          )}
          <Field orientation="horizontal">
            <Checkbox id="oidc-dpop" checked={draft.dpop} onCheckedChange={(on) => patch({ dpop: on === true })} />
            <div className="flex flex-col gap-0.5">
              <FieldLabel htmlFor="oidc-dpop">DPoP 필수</FieldLabel>
              <FieldDescription>토큰 요청마다 소유 증명(DPoP) 헤더를 요구합니다.</FieldDescription>
            </div>
          </Field>
        </FieldGroup>
      </SettingRow>

      {service ? (
        <SettingRow title="범위" description="이 앱이 요청할 수 있는 범위입니다. API가 정한 이름을 그대로 넣으세요.">
          <UriListField
            label="범위"
            addLabel="범위 추가"
            placeholder="reports.read"
            values={draft.scopes}
            onChange={(scopes) => patch({ scopes })}
            max={20}
          />
        </SettingRow>
      ) : (
        <>
          <SettingRow
            title="로그인 리다이렉트 주소"
            description="로그인이 끝나면 인증 응답과 코드를 이 주소로 보냅니다."
          >
            <UriListField
              label="로그인 리다이렉트 주소"
              placeholder={type === 'native' ? 'myapp://callback' : 'https://app.example.com/callback'}
              values={draft.redirectUris}
              onChange={(redirectUris) => patch({ redirectUris })}
            />
          </SettingRow>
          <SettingRow
            title="로그아웃 리다이렉트 주소"
            description="앱이 세션을 닫은 뒤 사용자를 이 주소 중 하나로 돌려보냅니다. 선택 사항입니다."
          >
            <UriListField
              label="로그아웃 리다이렉트 주소"
              placeholder="https://app.example.com"
              allowEmpty
              values={draft.postLogoutRedirectUris}
              onChange={(postLogoutRedirectUris) => patch({ postLogoutRedirectUris })}
            />
          </SettingRow>
          <SettingRow title="받을 수 있는 정보" description="앱이 사용자에 대해 읽을 수 있는 항목입니다. 기본 신원 정보(openid)는 항상 포함됩니다.">
            <FieldGroup className="gap-3">
              {USER_SCOPES.map((scope) => (
                <Field key={scope.key} orientation="horizontal">
                  <Checkbox
                    id={`oidc-scope-${scope.key}`}
                    checked={draft.scopes.includes(scope.key)}
                    onCheckedChange={(on) =>
                      patch({ scopes: on === true ? [...draft.scopes, scope.key] : draft.scopes.filter((s) => s !== scope.key) })
                    }
                  />
                  <div className="flex flex-col gap-0.5">
                    <FieldLabel htmlFor={`oidc-scope-${scope.key}`}>{scope.label}</FieldLabel>
                    <FieldDescription>{scope.description}</FieldDescription>
                  </div>
                </Field>
              ))}
            </FieldGroup>
          </SettingRow>
        </>
      )}
    </>
  )
}
