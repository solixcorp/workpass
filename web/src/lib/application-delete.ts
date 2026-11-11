export type DeleteResult = {
  deleted: boolean
  providerRemoved?: boolean
  providerKind?: 'oidc' | 'saml' | 'wsfed' | 'swa' | null
  providerShared?: boolean
}

const PROVIDER_LABEL: Record<string, string> = {
  oidc: '로그인 클라이언트',
  saml: 'SAML 서비스 제공자',
  wsfed: 'WS-Fed 신뢰 당사자',
  swa: '비밀번호 대행 등록',
}

/** What the server did besides removing the app card, in one sentence. */
export function deleteMessage(result: DeleteResult): string {
  if (result.providerRemoved && result.providerKind) return `앱과 ${PROVIDER_LABEL[result.providerKind] ?? '연동'}을(를) 삭제했습니다.`
  if (result.providerShared) return '앱을 삭제했습니다. 같은 연동을 쓰는 다른 앱이 있어 연동은 남겨 두었습니다.'
  return '앱을 삭제했습니다.'
}
