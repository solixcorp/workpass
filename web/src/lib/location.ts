export type ShareOutcome = 'ok' | 'outside' | 'inaccurate' | 'blocked' | 'unavailable' | 'rate_limited'

/** The browser's own position, once the person allows it. */
export function currentPosition(): Promise<GeolocationPosition> {
  return new Promise((resolve, reject) => {
    if (!('geolocation' in navigator)) {
      reject(new Error('unsupported'))
      return
    }
    navigator.geolocation.getCurrentPosition(resolve, reject, { enableHighAccuracy: true, timeout: 15_000, maximumAge: 0 })
  })
}

/**
 * Ask the browser where it is and report that to the server, which keeps only
 * whether it is inside an allowed place (as a short-lived cookie).
 */
export async function shareLocation(): Promise<ShareOutcome> {
  let position: GeolocationPosition
  try {
    position = await currentPosition()
  } catch (error) {
    return (error as GeolocationPositionError)?.code === 1 ? 'blocked' : 'unavailable'
  }
  try {
    const response = await fetch('/api/location/proof', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ latitude: position.coords.latitude, longitude: position.coords.longitude, accuracy: position.coords.accuracy }),
    })
    const body = (await response.json().catch(() => ({}))) as { ok?: boolean; reason?: string }
    if (body.ok) return 'ok'
    if (body.reason === 'outside' || body.reason === 'inaccurate' || body.reason === 'rate_limited') return body.reason
    return 'unavailable'
  } catch {
    return 'unavailable'
  }
}
