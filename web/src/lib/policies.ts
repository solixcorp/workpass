export type PolicyType =
  | 'expression'
  | 'password'
  | 'password_expiry'
  | 'password_uniqueness'
  | 'reputation'
  | 'geoip'
  | 'event_matcher'

export type Policy = {
  id: string
  name: string
  type: PolicyType
  config: Record<string, unknown>
  enabled: boolean
  executionLogging: boolean
}

export type Binding = {
  id: string
  target: BindingTarget
  targetRef: string
  policyId: string | null
  bindUserId: string | null
  bindGroupId: string | null
  orderIndex: number
  mode: 'all' | 'any'
  negate: boolean
  failureResult: 'pass' | 'fail'
  enabled: boolean
  policyName: string | null
  policyType: string | null
}

export type BindingTarget = 'application' | 'login' | 'password_entry' | 'user_write' | 'notification_rule'

export const TYPE_INFO: Record<PolicyType, { label: string; description: string }> = {
  reputation: {
    label: '평판',
    description: '로그인 실패가 쌓인 IP나 아이디의 점수가 기준 아래로 내려가면 막습니다.',
  },
  geoip: {
    label: '위치',
    description: '허용한 국가나 네트워크(ASN)에서만, 또는 평소 위치에서 너무 멀지 않을 때만 통과시킵니다.',
  },
  event_matcher: {
    label: '이벤트 매처',
    description: '감사 이벤트가 조건(동작, 앱, IP, 질의)에 맞는지 판정합니다. 알림 규칙에 연결해 씁니다.',
  },
  password_expiry: {
    label: '비밀번호 만료',
    description: '비밀번호를 정한 지 정해진 일수가 지나면 새로 정하게 합니다.',
  },
  password_uniqueness: {
    label: '비밀번호 재사용 금지',
    description: '최근에 쓴 비밀번호는 다시 쓰지 못하게 합니다.',
  },
  password: {
    label: '비밀번호 복잡도',
    description: '길이, 문자 종류, 유출 여부, 강도를 검사합니다. 활성화 화면에는 설정 화면의 비밀번호 규칙을 쓰는 편이 쉽습니다.',
  },
  expression: {
    label: '식',
    description: '식으로 직접 판정 로직을 씁니다. 코드를 아는 관리자를 위한 고급 유형입니다.',
  },
}

export const TARGET_INFO: Record<BindingTarget, { label: string; refHint: string }> = {
  application: { label: '앱 접근', refHint: '앱 대상 (예: app:wiki)' },
  login: { label: '로그인', refHint: '대상 이름 (예: default)' },
  password_entry: { label: '비밀번호 입력', refHint: '대상 이름 (예: default)' },
  user_write: { label: '사용자 쓰기', refHint: '대상 이름 (예: default)' },
  notification_rule: { label: '알림 규칙', refHint: '알림 규칙 ID' },
}

/** A short summary of what a policy checks, for the list. */
export function summarize(policy: Policy): string {
  const c = policy.config
  switch (policy.type) {
    case 'reputation':
      return `${c.check === 'ip' ? 'IP' : c.check === 'username' ? '아이디' : 'IP와 아이디'} 점수 ${String(c.threshold ?? -3)} 이하면 거절`
    case 'geoip': {
      const parts: string[] = []
      if (Array.isArray(c.countries) && c.countries.length) parts.push(`국가 ${(c.countries as string[]).join(', ')}`)
      if (Array.isArray(c.asns) && c.asns.length) parts.push(`ASN ${(c.asns as number[]).join(', ')}`)
      if (typeof c.maxDistanceKm === 'number') parts.push(`평소 위치에서 ${c.maxDistanceKm}km 이내`)
      if (c.checkImpossibleTravel === true) parts.push('불가능한 이동 거절')
      return parts.join(' · ') || '조건 없음'
    }
    case 'event_matcher':
      return [c.action, c.app, c.clientIp, c.query].filter(Boolean).join(' · ') || '조건 없음'
    case 'password_expiry':
      return `${String(c.days ?? 180)}일 후 만료${c.denyOnly === true ? ' (거절만, 변경 요구 없음)' : ''}`
    case 'password_uniqueness':
      return `최근 ${String(c.count ?? 5)}개 재사용 금지`
    case 'password':
      return `최소 ${String(c.minLength ?? 12)}자${c.checkHibp === true ? ' · 유출 검사' : ''}${c.checkStrength === true ? ' · 강도 검사' : ''}`
    case 'expression':
      return String(c.expression ?? '').split('\n')[0]!.slice(0, 80)
  }
}
