export type AccessRequest = {
  id: string
  subject: string
  userId: string
  bindingId: string
  justification: string
  status: 'pending' | 'approved' | 'denied' | 'cancelled' | 'lapsed' | 'revoked'
  requestedExpirySeconds: number
  grantedExpiresAt: string | null
  pendingExpiresAt: string
  decidedAt: string | null
  decidedBy: string | null
  decisionNote: string | null
  createdAt: string
  displayName: string | null
}

export type Requestable = {
  subject: string
  displayName: string | null
  pendingExpirySeconds: number
  maxGrantedExpirySeconds: number
}

export const STATUS_LABELS: Record<AccessRequest['status'], string> = {
  pending: '검토 중',
  approved: '승인됨',
  denied: '거절됨',
  cancelled: '취소됨',
  lapsed: '기한 지남',
  revoked: '회수됨',
}

/** "app:slug" style subjects read better without the protocol prefix. */
export function subjectLabel(subject: string, displayName: string | null): string {
  if (displayName) return displayName
  return subject.slice(subject.indexOf(':') + 1)
}

export function formatDuration(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}일`
  if (seconds % 3600 === 0) return `${seconds / 3600}시간`
  return `${Math.round(seconds / 60)}분`
}
