/**
 * WorkPass: the fixed, first-party OAuth2/OIDC client behind the user portal
 * and admin console. The SPA signs in through the same authorization-code +
 * PKCE flow any relying party uses, so portal logins are audited and policy
 * gated like every other OIDC login. The client is public (no secret),
 * PKCE-only and skips the consent screen because it is operated by the IdP.
 *
 * The scope names are WorkPass' own. They gate what a WorkPass token may do;
 * the portal itself authorizes requests with the HttpOnly session cookie.
 */

import type { Env } from "../env";

export const WORKPASS_CLIENT_ID = "workpass";
export const WORKPASS_CLIENT_NAME = "WorkPass Dashboard";
export const WORKPASS_CALLBACK_PATH = "/enduser/callback";
export const WORKPASS_SLUG = "workpass-dashboard";

export const WORKPASS_SCOPES = [
  "workpass.users.read.self",
  "workpass.users.manage.self",
  "workpass.internal.enduser.read",
  "workpass.internal.enduser.manage",
  "workpass.enduser.dashboard.read",
  "workpass.enduser.dashboard.manage",
  "workpass.myAccount.sessions.manage",
  "workpass.internal.navigation.enduser.read",
] as const;

/** Scopes any registered client may request (advertised in discovery). */
export const STANDARD_SCOPES = ["openid", "profile", "email", "offline_access", "phone", "groups"] as const;

export function workpassRedirectUri(env: Env): string {
  return `${new URL(env.AUTH_BASE_URL).origin}${WORKPASS_CALLBACK_PATH}`;
}

/**
 * Create or refresh the WorkPass client row. Idempotent. Redirect URI and
 * scopes follow the deployment; `disabled` is left alone so an operator who
 * disabled the client stays in control across migrations.
 */
export async function ensureWorkPassClient(env: Env): Promise<void> {
  const table = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'oauthClient'",
  ).first<{ name: string }>();
  if (!table) return;

  const now = new Date().toISOString();
  const scopes = JSON.stringify(["openid", "profile", "email", ...WORKPASS_SCOPES]);
  const redirectUris = JSON.stringify([workpassRedirectUri(env)]);
  const existing = await env.DB.prepare('SELECT id FROM "oauthClient" WHERE clientId = ?')
    .bind(WORKPASS_CLIENT_ID).first<{ id: string }>();

  if (existing) {
    await env.DB.prepare(
      `UPDATE "oauthClient" SET name = ?, redirectUris = ?, scopes = ?, grantTypes = ?, responseTypes = ?,
         tokenEndpointAuthMethod = 'none', applicationType = 'web', skipConsent = 1, requirePKCE = 1,
         clientSecret = NULL, updatedAt = ? WHERE clientId = ?`,
    ).bind(
      WORKPASS_CLIENT_NAME, redirectUris, scopes,
      JSON.stringify(["authorization_code"]), JSON.stringify(["code"]), now, WORKPASS_CLIENT_ID,
    ).run();
    return;
  }

  await env.DB.prepare(
    `INSERT INTO "oauthClient"
       (id, clientId, name, redirectUris, scopes, grantTypes, responseTypes, tokenEndpointAuthMethod,
        applicationType, skipConsent, requirePKCE, disabled, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'none', 'web', 1, 1, 0, ?, ?)`,
  ).bind(
    crypto.randomUUID(), WORKPASS_CLIENT_ID, WORKPASS_CLIENT_NAME, redirectUris, scopes,
    JSON.stringify(["authorization_code"]), JSON.stringify(["code"]), now, now,
  ).run();
}

/** The registry row that lists the dashboard next to every other app. */
export async function ensureWorkPassApplication(env: Env): Promise<void> {
  const table = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'applications'",
  ).first<{ name: string }>();
  if (!table) return;
  const now = new Date().toISOString();
  const launchUrl = `${new URL(env.AUTH_BASE_URL).origin}/`;
  await env.DB.prepare(
    `INSERT INTO applications
       (id, slug, name, description, protocol, binding, launch_url, icon_url, category_group,
        hide_from_dashboard, enabled, created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'oidc', ?, ?, '/workpass.svg', NULL, 0, 1, 'system', ?, ?)
     ON CONFLICT(slug) DO UPDATE SET name = excluded.name, binding = excluded.binding,
       launch_url = excluded.launch_url, enabled = 1, updated_at = excluded.updated_at`,
  ).bind(
    crypto.randomUUID(), WORKPASS_SLUG, WORKPASS_CLIENT_NAME, "사내 계정 포털과 관리자 콘솔",
    WORKPASS_CLIENT_ID, launchUrl, now, now,
  ).run();
}
