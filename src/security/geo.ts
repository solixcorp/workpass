/**
 * Travel-plausibility helpers for the device-risk pipeline.
 *
 * Geo positions come from two sources, in priority order:
 * 1. Event coordinates when the Fingerprint Server API returns geolocation
 *    latitude/longitude for the login IP (higher plan tiers).
 * 2. A coarse country centroid when only a two-letter country code is
 *    available (every plan).
 *
 * Country centroids deliberately model large regions: distances derived from
 * them are lower bounds for real travel, never evidence of real movement. Per
 * docs/security/device-risk-and-trust.md, no geo signal may be a standalone
 * verdict; results feed the shared allow/step_up/deny policy only.
 */

export interface GeoPoint {
  latitude: number;
  longitude: number;
  /** Where the coordinates came from; recorded with the observation. */
  source: "event" | "country";
}

export interface TravelObservation {
  latitude: number | null;
  longitude: number | null;
  countryCode: string | null;
  occurredAt: number;
}

/** Haversine distance in kilometers between two lat/lon points. */
export function haversineKm(a: GeoPoint, b: GeoPoint): number {
  const toRad = Math.PI / 180;
  const dLat = (b.latitude - a.latitude) * toRad;
  const dLon = (b.longitude - a.longitude) * toRad;
  const sinLat = Math.sin(dLat / 2);
  const sinLon = Math.sin(dLon / 2);
  const central =
    sinLat * sinLat +
    Math.cos(a.latitude * toRad) * Math.cos(b.latitude * toRad) * sinLon * sinLon;
  return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(central)));
}

/** ISO 3166-1 alpha-2 representative coordinates ([lat, lon], degrees). */
const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  AE: [24.0, 54.0], AF: [33.94, 67.71], AL: [41.15, 20.17], AM: [40.07, 45.04],
  AO: [-11.2, 17.87], AR: [-38.42, -63.62], AT: [47.52, 14.55], AU: [-25.27, 133.78],
  AZ: [40.14, 47.58], BA: [43.92, 17.68], BD: [23.68, 90.36], BE: [50.5, 4.47],
  BG: [42.73, 25.49], BH: [25.93, 50.64], BI: [-3.37, 29.92], BJ: [9.31, 2.32],
  BN: [4.54, 114.73], BO: [-16.29, -63.59], BR: [-14.24, -51.93], BS: [25.03, -77.4],
  BT: [27.51, 90.43], BW: [-22.33, 24.68], BY: [53.71, 27.95], BZ: [17.19, -88.5],
  CA: [56.13, -106.35], CD: [-4.04, 21.76], CF: [6.61, 20.94], CG: [-0.23, 15.83],
  CH: [46.82, 8.23], CI: [7.54, -5.55], CL: [-35.68, -71.54], CM: [7.37, 12.35],
  CN: [35.86, 104.2], CO: [4.57, -74.3], CR: [9.75, -83.75], CU: [21.52, -77.78],
  CV: [16.0, 24.0], CY: [35.13, 33.43], CZ: [49.82, 15.47], DE: [51.17, 10.45],
  DJ: [11.83, 42.59], DK: [56.26, 9.5], DM: [15.41, -61.37], DO: [18.74, -70.16],
  DZ: [28.03, 1.66], EC: [-1.83, -78.18], EE: [58.6, 25.01], EG: [26.82, 30.8],
  ER: [15.18, 39.78], ES: [40.46, -3.75], ET: [9.15, 40.49], FI: [61.92, 25.75],
  FJ: [-17.71, 178.07], FM: [7.43, 150.55], FO: [61.89, -6.91], FR: [46.23, 2.21],
  GA: [-0.8, 11.61], GB: [55.38, -3.44], GD: [12.12, -61.68], GE: [42.32, 43.36],
  GH: [7.95, -1.02], GI: [36.14, -5.35], GL: [71.71, -42.6], GM: [13.44, -15.31],
  GN: [9.95, -9.7], GQ: [1.65, 10.27], GR: [39.07, 21.82], GT: [15.78, -90.23],
  GU: [13.44, 144.79], GW: [11.8, -15.18], GY: [4.86, -58.93], HK: [22.4, 114.11],
  HN: [15.2, -86.24], HR: [45.1, 15.2], HT: [18.97, -72.29], HU: [47.16, 19.5],
  ID: [-0.79, 113.92], IE: [53.41, -8.24], IL: [31.05, 34.85], IN: [20.59, 78.96],
  IQ: [33.22, 43.68], IR: [32.43, 53.69], IS: [64.96, -19.02], IT: [41.87, 12.57],
  JM: [18.11, -77.3], JO: [30.81, 36.24], JP: [36.2, 138.25], KE: [-0.02, 37.91],
  KG: [41.2, 74.77], KH: [12.56, 104.99], KM: [-11.65, 43.33], KP: [40.34, 127.51],
  KR: [35.91, 127.77], KW: [29.31, 47.48], KZ: [48.02, 66.92], LA: [19.86, 102.5],
  LB: [33.85, 35.86], LC: [13.91, -60.98], LI: [47.17, 9.56], LK: [7.87, 80.77],
  LR: [6.43, -9.43], LS: [-29.61, 28.23], LT: [55.17, 23.88], LU: [49.82, 6.13],
  LV: [56.88, 24.6], LY: [26.34, 17.23], MA: [31.79, -7.09], MC: [43.75, 7.41],
  MD: [47.41, 28.37], ME: [42.71, 19.37], MG: [-18.77, 46.87], MK: [41.61, 21.75],
  ML: [17.57, -4.0], MM: [21.91, 95.96], MN: [46.86, 103.85], MO: [22.2, 113.54],
  MR: [21.01, -10.94], MT: [35.94, 14.38], MU: [-20.35, 57.55], MV: [3.2, 73.22],
  MW: [-13.25, 34.3], MX: [23.63, -102.55], MY: [4.21, 101.98], MZ: [-18.67, 35.53],
  NA: [-22.96, 18.49], NC: [-20.9, 165.24], NE: [17.61, 8.08], NG: [9.08, 8.68],
  NI: [12.87, -85.21], NL: [52.13, 5.29], NO: [60.47, 8.47], NP: [28.39, 84.12],
  NZ: [-40.9, 174.89], OM: [21.51, 55.92], PA: [8.54, -80.78], PE: [-9.19, -75.02],
  PF: [-17.68, -149.41], PG: [-6.31, 143.96], PH: [12.88, 121.77], PK: [30.38, 69.35],
  PL: [51.92, 19.15], PR: [18.22, -66.59], PS: [31.95, 35.23], PT: [39.4, -8.22],
  PY: [-23.44, -58.44], QA: [25.35, 51.18], RO: [45.94, 24.97], RS: [44.02, 21.01],
  RU: [61.52, 105.32], RW: [-1.94, 29.87], SA: [23.89, 45.08], SB: [-9.65, 160.16],
  SC: [-4.68, 55.49], SD: [12.86, 30.22], SE: [60.13, 18.64], SG: [1.35, 103.82],
  SI: [46.15, 14.99], SK: [48.67, 19.7], SL: [8.46, -11.78], SM: [43.94, 12.45],
  SN: [14.5, -14.45], SO: [5.15, 46.2], SR: [3.94, -56.03], SS: [6.88, 31.31],
  SV: [13.79, -88.9], SY: [34.8, 38.99], SZ: [-26.52, 31.47], TD: [15.45, 18.73],
  TG: [8.62, 0.82], TH: [15.87, 100.99], TJ: [38.86, 71.28], TL: [-8.87, 125.73],
  TM: [38.97, 59.56], TN: [30.38, 9.54], TO: [-21.18, -175.2], TR: [38.96, 35.24],
  TT: [10.69, -61.22], TW: [23.7, 120.96], TZ: [-6.37, 34.89], UA: [48.38, 31.17],
  UG: [1.37, 32.29], US: [39.83, -98.58], UY: [-32.52, -55.77], UZ: [41.38, 64.59],
  VA: [41.9, 12.45], VC: [12.98, -61.29], VE: [6.42, -66.59], VG: [18.42, -64.64],
  VN: [14.06, 108.28], VU: [-15.38, 166.96], WS: [-13.76, -172.1], XK: [42.6, 20.9],
  YE: [15.55, 48.52], ZA: [-30.56, 22.94], ZM: [-13.13, 27.85], ZW: [-19.02, 29.15],
};

/**
 * Resolve a comparable geo point for a login observation.
 * Event-supplied coordinates win when present and plausible; otherwise a
 * country centroid is used. Countries without a centroid entry resolve to
 * null (no travel comparison) rather than a fabricated location.
 */
export function resolveGeoPoint(input: {
  latitude: number | null;
  longitude: number | null;
  countryCode: string | null;
}): GeoPoint | null {
  const { latitude, longitude, countryCode } = input;
  if (
    latitude !== null &&
    longitude !== null &&
    Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    Math.abs(latitude) <= 90 &&
    Math.abs(longitude) <= 180
  ) {
    return { latitude, longitude, source: "event" };
  }
  if (countryCode) {
    const centroid = COUNTRY_CENTROIDS[countryCode];
    if (centroid) return { latitude: centroid[0], longitude: centroid[1], source: "country" };
  }
  return null;
}
