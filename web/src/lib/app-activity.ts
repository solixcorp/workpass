import { queryOptions } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

export type Risk = { action: string; reasons: string[]; at: string | null; scope: 'app' | 'session' | null }

export type ActivityApp = {
  subject: string
  name: string
  slug: string | null
  protocol: string
  signIns: number
  lastAt: string | null
  lastRisk: Risk | null
  consent: { scopes: string[]; grantedAt: string | null; updatedAt: string | null } | null
}

export type ActivityEvent = {
  id: string
  subject: string
  app: { name: string; slug: string | null; protocol: string }
  kind: 'consent' | 'sign_in'
  scopes: string[]
  method: string | null
  at: string
  risk: Risk | null
  country: string | null
}

export const appActivityQuery = (userId: string) =>
  queryOptions({
    queryKey: ['admin', 'user', userId, 'app-activity'],
    queryFn: () => apiFetch<{ apps: ActivityApp[]; events: ActivityEvent[] }>(`/api/admin/users/${userId}/app-activity`),
  })

export const KIND_LABELS: Record<ActivityEvent['kind'], string> = {
  consent: '권한 허용',
  sign_in: '로그인',
}

export const METHOD_LABELS: Record<string, string> = { saml: 'SAML', wsfed: 'WS-Fed', swa: 'SWA' }

export const SCOPE_LABELS: Record<string, string> = {
  openid: '기본 신원 정보',
  profile: '프로필',
  email: '이메일',
  phone: '전화번호',
  groups: '그룹',
  offline_access: '오래 유지되는 접근',
}

export const RISK_ACTIONS: Record<string, { label: string; tone: 'secondary' | 'outline' | 'destructive' }> = {
  allow: { label: '정상', tone: 'secondary' },
  observe: { label: '관찰만', tone: 'outline' },
  step_up: { label: '추가 인증 요구', tone: 'outline' },
  deny: { label: '거절', tone: 'destructive' },
}

export const REASON_LABELS: Record<string, string> = {
  untrusted_device: '신뢰하지 않은 기기',
  tampering_detected: '변조 감지',
  suspect_score_threshold: '의심 점수 초과',
  rapid_network_change: '짧은 시간에 네트워크 변경',
  rapid_device_change: '짧은 시간에 기기 변경',
  rapid_device_and_country_change: '짧은 시간에 기기와 국가 변경',
  mitm_attack_detected: '중간자 공격 의심',
  low_identification_confidence: '기기 식별 신뢰도 낮음',
  location_spoofing_detected: '위치 위조 의심',
  vpn_detected: 'VPN 사용',
  proxy_detected: '프록시 사용',
  datacenter_ip_detected: '데이터센터 IP',
  tor_network_detected: 'Tor 네트워크 접속',
  ip_blocklisted: '위험 IP 목록 일치',
  incognito_detected: '시크릿 모드 접속',
  privacy_settings_detected: '개인정보 보호 설정 기기',
  developer_tools_detected: '개발자 도구 실행 기기',
  virtual_machine_detected: '가상머신 접속',
  simulator_detected: '시뮬레이터 기기',
  rare_device_detected: '드문 기기',
  high_activity_device_detected: '과도하게 활발한 기기',
  impossible_travel: '불가능한 이동',
  history_distance_exceeded: '평소 위치에서 멀리 떨어짐',
  geo_position_unavailable: '위치를 확인하지 못함',
  bot_detected: '봇으로 감지',
  replayed_event: '이미 쓴 기기 확인값 재사용',
  missing_event: '기기 확인값 없음',
  invalid_event: '기기 확인값이 올바르지 않음',
  provider_unavailable: '기기 확인 서비스에 연결하지 못함',
  lookup_rate_limited: '기기 확인 요청 한도 초과',
  risk_store_unavailable: '위험 기록 저장소 오류',
  risk_evaluation_unavailable: '위험 평가 오류',
  observation_unavailable: '관측 기록 오류',
  event_not_bound_to_user: '기기 확인값이 이 사용자 것이 아님',
  mfa_required: '관리자가 2차 인증을 요구함',
}
