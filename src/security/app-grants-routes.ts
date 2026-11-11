/**
 * Administrator view of one user's connected apps: what they allowed, when,
 * how often they signed in, and the device-risk verdict at each moment.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "./authorization";

export const appGrantRoutes = new Hono<{ Bindings: Env }>();

function scopesOf(value: unknown): string[] {
  if (typeof value !== "string" || !value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.filter((entry): entry is string => typeof entry === "string");
  } catch {
    // Space separated.
  }
  return value.split(/[ ,]+/).filter(Boolean);
}

function isoOf(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const date = new Date(typeof value === "string" && /^\d+$/.test(value) ? Number(value) : (value as string | number));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

interface EventRow {
  id: string;
  subject: string;
  kind: "consent" | "sign_in";
  scopes: string | null;
  method: string | null;
  at: string;
  riskAction: string | null;
  riskReasons: string | null;
  riskAt: string | null;
  riskScope: string | null;
  country: string | null;
}

appGrantRoutes.get("/users/:id/app-activity", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  context.header("Cache-Control", "no-store");
  const userId = context.req.param("id");
  const db = context.env.DB;

  const user = await db.prepare('SELECT id FROM "user" WHERE id = ?').bind(userId).first();
  if (!user) return context.json({ error: "사용자를 찾을 수 없습니다." }, 404);

  const grants = await db.prepare(
    `SELECT id, subject, kind, scopes, method, occurred_at AS at, risk_action AS riskAction,
            risk_reasons AS riskReasons, risk_at AS riskAt, risk_scope AS riskScope, country_code AS country
     FROM app_grant_events WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 300`,
  ).bind(userId).all<EventRow>().then((r) => r.results).catch(() => [] as EventRow[]);

  // Sign-ins recorded before grants were kept: no verdict, but the fact and the time.
  const history = await db.prepare(
    "SELECT subject, issued_at AS at, method FROM app_issuance_history WHERE user_id = ? ORDER BY issued_at DESC LIMIT 300",
  ).bind(userId).all<{ subject: string; at: string; method: string | null }>().then((r) => r.results).catch(() => []);
  const near = (subject: string, at: string) =>
    grants.some((grant) => grant.subject === subject && Math.abs(Date.parse(grant.at) - Date.parse(at)) < 5000);
  const legacy: EventRow[] = history
    .filter((row) => !near(row.subject, row.at))
    .map((row) => ({
      id: `history:${row.subject}:${row.at}`, subject: row.subject, kind: "sign_in" as const, scopes: null,
      method: row.method, at: row.at, riskAction: null, riskReasons: null, riskAt: null, riskScope: null, country: null,
    }));

  const consents = await db.prepare(
    'SELECT clientId, scopes, createdAt, updatedAt FROM "oauthConsent" WHERE userId = ?',
  ).bind(userId).all<{ clientId: string; scopes: string; createdAt: unknown; updatedAt: unknown }>()
    .then((r) => r.results).catch(() => []);

  const events = [...grants, ...legacy].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 300);

  // Names: the app registry first, then the OAuth client's own name.
  const registry = await db.prepare("SELECT slug, name, protocol, binding FROM applications")
    .all<{ slug: string; name: string; protocol: string; binding: string | null }>().then((r) => r.results).catch(() => []);
  const clients = await db.prepare('SELECT clientId, name FROM "oauthClient"')
    .all<{ clientId: string; name: string | null }>().then((r) => r.results).catch(() => []);
  const describe = (subject: string) => {
    const app = registry.find((entry) => entry.binding && `${entry.protocol}:${entry.binding}` === subject);
    if (app) return { name: app.name, slug: app.slug, protocol: app.protocol };
    const [protocol, ...rest] = subject.split(":");
    const key = rest.join(":");
    const client = protocol === "oidc" ? clients.find((entry) => entry.clientId === key) : null;
    return { name: client?.name ?? key, slug: null, protocol: protocol ?? "" };
  };
  const risk = (row: EventRow) =>
    row.riskAction
      ? {
          action: row.riskAction,
          reasons: (() => { try { return JSON.parse(row.riskReasons ?? "[]") as string[]; } catch { return []; } })(),
          at: row.riskAt,
          scope: row.riskScope,
        }
      : null;

  const view = events.map((row) => ({
    id: row.id,
    subject: row.subject,
    app: describe(row.subject),
    kind: row.kind,
    scopes: scopesOf(row.scopes),
    method: row.method,
    at: row.at,
    risk: risk(row),
    country: row.country,
  }));

  const subjects = new Set<string>([...view.map((event) => event.subject), ...consents.map((c) => `oidc:${c.clientId}`)]);
  const apps = [...subjects].map((subject) => {
    const mine = view.filter((event) => event.subject === subject);
    const signIns = mine.filter((event) => event.kind === "sign_in" || event.kind === "consent");
    const consent = consents.find((c) => `oidc:${c.clientId}` === subject);
    return {
      subject,
      ...describe(subject),
      signIns: signIns.length,
      lastAt: mine[0]?.at ?? null,
      lastRisk: mine.find((event) => event.risk)?.risk ?? null,
      consent: consent ? { scopes: scopesOf(consent.scopes), grantedAt: isoOf(consent.createdAt), updatedAt: isoOf(consent.updatedAt) } : null,
    };
  }).sort((a, b) => Date.parse(b.lastAt ?? b.consent?.grantedAt ?? "0") - Date.parse(a.lastAt ?? a.consent?.grantedAt ?? "0"));

  return context.json({ apps, events: view });
});
