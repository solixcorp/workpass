export type Person = { name: string; email: string } | null

export type AuditEvent = {
  id: string
  occurred_at: string
  actor_user_id: string | null
  target_user_id: string | null
  actor: Person
  target: Person
  event_type: string
  outcome: 'started' | 'success' | 'failure'
  request_path: string
  client_ip: string | null
  event_context: string | null
}

export type AuditPage = { events: AuditEvent[]; page?: number; total?: number; limit: number; nextCursor: string | null }
