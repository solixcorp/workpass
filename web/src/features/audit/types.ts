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
  /** Where the address is, as the edge saw it when the event happened; null for older events. */
  client_geo?: { country: string | null; region: string | null; city: string | null; asn: string | null } | null
  event_context: string | null
}

export type AuditPage = { events: AuditEvent[]; page?: number; total?: number; limit: number; nextCursor: string | null }

export type QueryField = { name: string; aliases: string[]; description: string; operators: string[]; examples: string[] }
export type QueryHelp = { fields: QueryField[]; examples: Array<{ title: string; query: string }> }

/** A short, readable place for an address: "서울, KR". */
export function placeOf(geo: AuditEvent['client_geo']): string | null {
  if (!geo) return null
  return [geo.city, geo.region && geo.region !== geo.city ? geo.region : null, geo.country].filter(Boolean).join(', ') || null
}
