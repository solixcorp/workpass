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
}
