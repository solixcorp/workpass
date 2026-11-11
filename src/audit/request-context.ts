import { AsyncLocalStorage } from "node:async_hooks";

export interface AuditGeo { country: string | null; region: string | null; city: string | null; asn: string | null; timezone: string | null }
export const auditRequestContext = new AsyncLocalStorage<{ ip: string | null; geo: AuditGeo | null }>();

export function auditContextForRequest(request: Request) {
  const cf = (request as Request & { cf?: Record<string, unknown> }).cf;
  const text = (value: unknown) => typeof value === "string" ? value : typeof value === "number" && Number.isFinite(value) ? String(value) : null;
  const geo = cf ? { country: text(cf.country), region: text(cf.region), city: text(cf.city), asn: text(cf.asn), timezone: text(cf.timezone) } : null;
  return {
    ip: request.headers.get("cf-connecting-ip") ?? request.headers.get("x-real-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null,
    geo: geo && Object.values(geo).some(Boolean) ? geo : null,
  };
}

export function auditClientGeo(raw: unknown): { country: string | null; region: string | null; city: string | null; asn: string | null } | null {
  try {
    const obj = typeof raw === "string" ? JSON.parse(raw) : raw;
    const geo = obj && typeof obj === "object" ? obj.geo : null;
    if (!geo || typeof geo !== "object" || Array.isArray(geo)) return null;
    const field = (key: string) => typeof geo[key] === "string" ? geo[key] : null;
    return { country: field("country"), region: field("region"), city: field("city"), asn: field("asn") };
  } catch { return null; }
}
