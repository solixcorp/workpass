import { Hono } from "hono";
import {
  oauthProviderAuthServerMetadata,
  oauthProviderOpenIdConfigMetadata,
} from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { createAuth } from "./config";
import { auditAuthRequest } from "../audit/auth-middleware";
import { logoutScreenRedirect } from "./logout-pages";
import { evaluateAppAccess, loadAppAccessPolicy } from "../access/policies";
import { insertAuditEvent } from "../audit/store";

export const authRoutes = new Hono<{ Bindings: Env }>();

authRoutes.get("/.well-known/openid-configuration", (context) =>
  oauthProviderOpenIdConfigMetadata(createAuth(context.env))(context.req.raw),
);

authRoutes.get("/.well-known/oauth-authorization-server/api/auth", (context) =>
  oauthProviderAuthServerMetadata(createAuth(context.env))(context.req.raw),
);

/**
 * Rebuilding a request drops the Cloudflare edge data (`request.cf`: country,
 * region, city, coordinates), which left passkey sign-ins without a location.
 * Carry it over to the rebuilt request.
 */
export function rebuildRequest(original: Request, url: URL | string, init: RequestInit): Request {
  const next = new Request(url, init);
  const cf = (original as Request & { cf?: unknown }).cf;
  if (cf !== undefined && (next as Request & { cf?: unknown }).cf === undefined) {
    try {
      Object.defineProperty(next, "cf", { value: cf, enumerable: true });
    } catch {
      // A runtime that keeps `cf` read-only already copied it.
    }
  }
  return next;
}

/** Prevent the provider's pre-validation hook from starting an internal authorize. */
export async function stripUntrustedOAuthQuery(request: Request): Promise<Request> {
  const url = new URL(request.url);
  if (["/api/auth/oauth2/authorize", "/api/auth/oauth2/consent", "/api/auth/oauth2/continue"].includes(url.pathname)) return request;
  url.searchParams.delete("oauth_query");
  if (request.method === "GET" || request.method === "HEAD") return rebuildRequest(request, url, request as unknown as RequestInit);
  const type = (request.headers.get("content-type") ?? "").toLowerCase();
  let body: BodyInit | null = null;
  if (/^application\/([a-z0-9.+-]*\+)?json/.test(type)) {
    const text = await request.clone().text();
    try {
      const value = JSON.parse(text);
      if (value && typeof value === "object" && !Array.isArray(value)) delete value.oauth_query;
      body = JSON.stringify(value);
    } catch { body = text; }
  } else if (type.includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(await request.clone().text());
    params.delete("oauth_query");
    body = params.toString();
  } else if (type.includes("multipart/form-data")) {
    const form = await request.clone().formData();
    form.delete("oauth_query");
    const headers = new Headers(request.headers);
    headers.delete("content-type");
    headers.delete("content-length");
    return rebuildRequest(request, url, { method: request.method, headers, body: form, redirect: request.redirect });
  } else {
    return rebuildRequest(request, url, request as unknown as RequestInit);
  }
  const headers = new Headers(request.headers);
  headers.delete("content-length");
  return rebuildRequest(request, url, { method: request.method, headers, body, redirect: request.redirect });
}

/** Provider defaults: unprefixed refresh tokens stored as unpadded base64url SHA-256. */
export async function enforceRefreshEntitlement(request: Request, env: Env): Promise<Response | null> {
  if (request.method !== "POST" || new URL(request.url).pathname !== "/api/auth/oauth2/token") return null;
  let userId: string | null = null;
  const rejection = await checkRefreshEntitlement(request, env, (id) => { userId = id; });
  if (rejection) {
    try {
      await insertAuditEvent(env, {
        id: crypto.randomUUID(), actor_user_id: userId, target_user_id: userId,
        event_type: "authorization.refresh_denied", outcome: "success",
        request_path: "/api/auth/oauth2/token",
      });
    } catch {
      return Response.json({ error: "Audit event could not be recorded" }, { status: 503, headers: { "Cache-Control": "no-store" } });
    }
  }
  return rejection;
}

async function checkRefreshEntitlement(request: Request, env: Env, resolvedUser: (id: string) => void): Promise<Response | null> {
  const invalid = () => Response.json({ error: "invalid_grant", error_description: "invalid refresh token" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  try {
    const type = (request.headers.get("content-type") ?? "").toLowerCase();
    let grant: unknown, token: unknown;
    if (type.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(await request.clone().text());
      if (params.getAll("grant_type").length !== 1) return invalid();
      grant = params.get("grant_type"); token = params.get("refresh_token");
      if (grant === "refresh_token" && params.getAll("refresh_token").length !== 1) return invalid();
    } else if (type.includes("application/json")) {
      const body = await request.clone().json() as Record<string, unknown>;
      grant = body?.grant_type; token = body?.refresh_token;
    } else if (type.includes("multipart/form-data")) {
      const params = await request.clone().formData();
      if (params.getAll("grant_type").length !== 1) return invalid();
      grant = params.get("grant_type"); token = params.get("refresh_token");
      if (grant === "refresh_token" && params.getAll("refresh_token").length !== 1) return invalid();
    } else {
      // Do not let an alternative body encoding bypass this gate.
      return Response.json({ error: "invalid_request" }, { status: 400 });
    }
    if (grant !== "refresh_token") return null;
    if (typeof token !== "string" || !token || token.length > 8192) return invalid();
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
    const hash = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const row = await env.DB.prepare('SELECT "userId", "clientId" FROM "oauthRefreshToken" WHERE token = ? LIMIT 1')
      .bind(hash).first<{ userId: string; clientId: string }>();
    if (!row?.userId || !row.clientId) return invalid();
    resolvedUser(row.userId);
    const policy = await loadAppAccessPolicy(env, `oidc:${row.clientId}`);
    // Refresh has no trustworthy session-bound MFA proof. We deliberately
    // enforce access only; MFA is checked at interactive authorization, not
    // re-proved on rotation (offline access can therefore outlive that proof).
    if (policy && !(await evaluateAppAccess(env, policy, row.userId)).allowed) return invalid();
    return null;
  } catch {
    return invalid(); // Policy or token lookup failure must never permit issuance.
  }
}

authRoutes.all("/api/auth/*", async (context) => {
  const rejection = await enforceRefreshEntitlement(context.req.raw, context.env);
  if (rejection) return rejection;
  const response = await auditAuthRequest(await stripUntrustedOAuthQuery(context.req.raw), context.env);
  return logoutScreenRedirect(context.req.raw, context.env, response);
});
