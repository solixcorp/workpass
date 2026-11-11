export type Place = { id: string; name: string; latitude: number; longitude: number; radiusM: number; enabled: boolean }

export type Policy = {
  mode: 'off' | 'observe' | 'enforce'
  signal: 'network' | 'browser' | 'network_or_browser'
  networkMarginKm: number
  maxAccuracyM: number
  exemptGroups: string[]
}

export type Verdict = {
  allowed: boolean
  pass: boolean
  mode: Policy['mode']
  method: 'off' | 'exempt' | 'network' | 'browser' | 'none'
  needsBrowser: boolean
  reason: 'ok' | 'outside' | 'no_signal' | 'needs_browser' | 'no_places'
  placeName: string | null
  distanceM: number | null
}

export type LocationView = {
  policy: Policy
  places: Place[]
  groups: Array<{ id: string; name: string }>
  edge: { available: boolean; country: string | null; city: string | null }
  self: Verdict
  /** A group's own set of places; its members are checked against these instead of the organization's. */
  groupRules?: Array<{ groupId: string; groupName: string; placeIds: string[] }>
  /** An app that can only be signed in to from certain places, with its own mode. */
  appRules?: Array<{ subject: string; applicationName: string | null; applicationSlug: string | null; placeIds: string[]; mode: 'observe' | 'enforce' }>
  /** Applications a rule can be made for. */
  applications?: Array<{ subject: string; name: string; slug: string }>
}
