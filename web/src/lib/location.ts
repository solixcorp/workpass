export type ShareOutcome = 'ok' | 'outside' | 'inaccurate' | 'blocked' | 'unavailable' | 'rate_limited'

function request(options: PositionOptions): Promise<GeolocationPosition> {
  return new Promise((resolve, reject) => {
    navigator.geolocation.getCurrentPosition(resolve, reject, options)
  })
}

/**
 * The browser's own position, once the person allows it.
 *
 * A precise fix (GPS or Wi-Fi) is tried first. Desktop browsers often cannot
 * produce one right away (macOS reports kCLErrorLocationUnknown as
 * POSITION_UNAVAILABLE), so a coarser network-based fix is tried next. A
 * denied permission is not retried.
 */
export async function currentPosition(): Promise<GeolocationPosition> {
  if (!('geolocation' in navigator)) throw new Error('unsupported')
  try {
    return await request({ enableHighAccuracy: true, timeout: 10_000, maximumAge: 0 })
  } catch (error) {
    if ((error as GeolocationPositionError)?.code === 1) throw error
  }
  return request({ enableHighAccuracy: false, timeout: 20_000, maximumAge: 60_000 })
}

/** Plain-language reason a position could not be read, for the person who asked for it. */
export function positionFailureMessage(error: unknown): string {
  const code = (error as GeolocationPositionError | undefined)?.code
  if (code === 1) return '브라우저가 위치 공유를 허용하지 않았습니다. 주소창의 위치 권한을 허용한 뒤 다시 시도하세요.'
  if (code === 2) return '기기가 현재 위치를 알아내지 못했습니다. Mac은 시스템 설정 → 개인정보 보호 및 보안 → 위치 서비스에서 브라우저를 켜고, Wi-Fi를 켠 상태로 잠시 후 다시 시도하세요. 급하면 위도와 경도를 직접 입력할 수 있습니다.'
  if (code === 3) return '위치를 읽는 데 시간이 너무 오래 걸렸습니다. 잠시 후 다시 시도하세요.'
  if ((error as Error | undefined)?.message === 'unsupported') return '이 브라우저는 위치 기능을 지원하지 않습니다.'
  return '현재 위치를 가져오지 못했습니다.'
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
