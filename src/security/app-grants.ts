/**
 * What a user allowed or signed in to, and how risky the device looked at that
 * moment. Each grant copies the verdict that was current (the app-specific
 * decision of the last few minutes when there is one, otherwise the login's)
 * so an administrator can read it later without the decision's retention.
 */

import type { Env } from "../env";

const APP_WINDOW_MS = 10 * 60 * 1000;
const SESSION_WINDOW_MS = 12 * 60 * 60 * 1000;

export type GrantKind = "consent" | "sign_in";

export interface GrantInput {
  userId: string;
  /** `oidc:<client id>`, `saml:<entity id>`, `wsfed:<realm>` or `swa:<origin>`. */
  subject: string;
  kind: GrantKind;
  scopes?: string[];
  method?: string | null;
}

async function currentRisk(env: Env, userId: string, subject: string) {
  const now = Date.now();
  try {
    const app = await env.DB.prepare(
      `SELECT action, reasons, occurred_at AS at FROM fingerprint_risk_decisions
       WHERE user_id = ? AND subject = ? AND occurred_at > ? ORDER BY occurred_at DESC LIMIT 1`,
    ).bind(userId, subject, new Date(now - APP_WINDOW_MS).toISOString())
      .first<{ action: string; reasons: string; at: string }>();
    if (app) return { ...app, scope: "app" as const };
    const session = await env.DB.prepare(
      `SELECT action, reasons, occurred_at AS at FROM fingerprint_risk_decisions
       WHERE user_id = ? AND occurred_at > ? ORDER BY occurred_at DESC LIMIT 1`,
    ).bind(userId, new Date(now - SESSION_WINDOW_MS).toISOString())
      .first<{ action: string; reasons: string; at: string }>();
    return session ? { ...session, scope: "session" as const } : null;
  } catch {
    return null;
  }
}

async function currentCountry(env: Env, userId: string): Promise<string | null> {
  try {
    const row = await env.DB.prepare(
      `SELECT country_code AS country FROM auth_device_observations
       WHERE user_id = ? AND occurred_at > ? ORDER BY occurred_at DESC LIMIT 1`,
    ).bind(userId, new Date(Date.now() - SESSION_WINDOW_MS).toISOString()).first<{ country: string | null }>();
    return row?.country ?? null;
  } catch {
    return null;
  }
}

/** Never throws: a failed record must not fail the sign-in it describes. */
export async function recordAppGrant(env: Env, input: GrantInput): Promise<void> {
  try {
    const risk = await currentRisk(env, input.userId, input.subject);
    await env.DB.prepare(
      `INSERT INTO app_grant_events
         (id, user_id, subject, kind, scopes, method, occurred_at, risk_action, risk_reasons, risk_at, risk_scope, country_code)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      crypto.randomUUID(), input.userId, input.subject.slice(0, 2100), input.kind,
      input.scopes && input.scopes.length ? JSON.stringify(input.scopes.slice(0, 40)) : null,
      input.method ?? null, new Date().toISOString(),
      risk?.action ?? null, risk?.reasons ?? null, risk?.at ?? null, risk?.scope ?? null,
      await currentCountry(env, input.userId),
    ).run();
  } catch {
    // The table does not exist before the first migration; nothing to record.
  }
}

function field(body: unknown, key: string): unknown {
  return body && typeof body === "object" ? (body as Record<string, unknown>)[key] : undefined;
}

/**
 * After the provider answered an authorization, consent or continue request:
 * if it handed out a code, record who allowed what. Reads copies of the
 * request and response and never changes either.
 */
export async function recordOAuthGrant(
  env: Env,
  request: { url: string; method: string; headers: Headers; clone(): { json(): Promise<unknown> } },
  response: Response,
  userId: string | null,
): Promise<void> {
  try {
    if (!userId) return;
    const path = new URL(request.url).pathname;
    const consent = request.method === "POST" && path === "/api/auth/oauth2/consent";
    const continued = request.method === "POST" && path === "/api/auth/oauth2/continue";
    const authorize = request.method === "GET" && path === "/api/auth/oauth2/authorize";
    if (!consent && !continued && !authorize) return;

    let issued = false;
    if (response.status >= 300 && response.status < 400) {
      issued = /[?&]code=/.test(response.headers.get("location") ?? "");
    } else if (response.ok) {
      const body = await response.clone().json().catch(() => null);
      const target = [field(body, "url"), field(body, "redirectURI"), field(body, "redirect_uri")]
        .find((value) => typeof value === "string") as string | undefined;
      issued = typeof target === "string" && /[?&]code=/.test(target);
    }
    if (!issued) return;

    let query: URLSearchParams;
    let scopes: string[] = [];
    if (authorize) {
      query = new URL(request.url).searchParams;
    } else {
      const body = await request.clone().json().catch(() => null);
      const signed = field(body, "oauth_query");
      if (typeof signed !== "string") return;
      query = new URLSearchParams(signed);
      const given = field(body, "scopes");
      if (consent && Array.isArray(given)) scopes = given.filter((entry): entry is string => typeof entry === "string");
      if (consent && field(body, "accept") === false) return;
    }
    const clientId = query.get("client_id");
    if (!clientId) return;
    if (scopes.length === 0) scopes = (query.get("scope") ?? "").split(/[ +]/).filter(Boolean);
    await recordAppGrant(env, {
      userId,
      subject: `oidc:${clientId}`,
      kind: consent ? "consent" : "sign_in",
      scopes,
    });
  } catch {
    // Observational only.
  }
}
