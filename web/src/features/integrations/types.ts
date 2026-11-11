export type Status = {
  scimOutbound: {
    enabled: boolean
    configured: boolean
    baseUrlHost: string | null
    operationCounts: { pending: number; in_progress: number; succeeded: number; failed: number; outcome_unknown: number }
    lastActivityAt: string | null
  }
  scimInbound: { enabled: boolean; configured: boolean; lastActivityAt: string | null }
  ssfSender: { enabled: boolean; configured: boolean; streamCount: number; lastActivityAt: string | null }
  ssfReceiver: { enabled: boolean; configured: boolean; streamCount: number; lastActivityAt: string | null }
  claims: { accountClaimsEnabled: boolean; attributeClaimsEnabled: boolean; scimAttributeReleaseEnabled: boolean; lastPolicyUpdateAt: string | null }
}

export type ScimOperation = {
  id: string
  target_id: string
  user_id: string
  operation: 'create' | 'update' | 'deactivate'
  status: 'pending' | 'in_progress' | 'succeeded' | 'failed' | 'outcome_unknown'
  remote_status: number | null
  created_at: string
  updated_at: string
  user_name: string | null
  user_email: string | null
  resolved_at?: string | null
  resolved_by_name?: string | null
  resolution_note?: string | null
  abandoned?: boolean
}

export type Stream = {
  id: string
  direction: 'sender' | 'receiver'
  deliveryMethod: string
  endpointHost: string | null
  status: string
  createdAt: string | null
  lastEventAt: string | null
  eventsDelivered: number | null
  eventsFailed: number | null
}

export type SignalEvent = {
  id: string
  streamId: string
  direction: 'sender' | 'receiver'
  state: string
  attempts: number | null
  httpStatus: number | null
  occurredAt: string
}

export type ClaimPolicy = {
  subject: string
  allowAccountClaims: boolean
  allowUserAttributes: boolean
  attributeAllowlist: string[] | null
  allowAccountAttributes: boolean
  allowGroupAttributes: boolean
  applicationName: string | null
  applicationSlug: string | null
}

export type UnpolicedApp = {
  subject: string
  applicationName: string
  applicationSlug: string
  defaults: Omit<ClaimPolicy, 'subject' | 'applicationName' | 'applicationSlug'>
}

export type Paged<K extends string, T> = { [key in K]: T[] } & { total: number; page: number; limit: number }
