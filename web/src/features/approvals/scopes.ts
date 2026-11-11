/** What a requested permission means to the person asked to allow it. */
const LABELS: Record<string, { title: string; description: string }> = {
  openid: { title: '내 신원 확인', description: '이 계정으로 로그인한 사람이 나임을 확인합니다.' },
  profile: { title: '프로필 정보', description: '이름과 프로필 정보를 읽습니다.' },
  email: { title: '이메일 주소', description: '이메일 주소와 확인 여부를 읽습니다.' },
  phone: { title: '휴대전화 번호', description: '휴대전화 번호와 확인 여부를 읽습니다.' },
  offline_access: { title: '로그인 유지', description: '내가 앱을 쓰지 않는 동안에도 로그인 상태를 이어 갑니다.' },
}

export function scopeLabel(scope: string): { title: string; description: string | null } {
  return LABELS[scope] ?? { title: scope, description: null }
}
