export type Account = {
  id: string
  name: string
  description: string
  createdBy: string
  createdAt: string
}

export type Membership = {
  role: 'admin' | 'member'
  grantedAt: string
  account: Account
  active: boolean
}

export const ROLE_LABELS: Record<Membership['role'], string> = {
  admin: '관리자',
  member: '멤버',
}
