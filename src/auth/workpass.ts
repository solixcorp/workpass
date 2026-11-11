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

/**
 * The id the client had before it became a per-deployment random value. Only
 * the migration reads it, to move an existing deployment over.
 */
export const LEGACY_WORKPASS_CLIENT_ID = "workpass";
const CLIENT_ID_KEY = "workpass.client_id";
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

function randomClientId(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  // 62 symbols into 256 values: reject the biased tail so every symbol is equally likely.
  let id = "";
  for (let i = 0; id.length < 24; i += 1) {
    const byte = i < bytes.length ? bytes[i]! : crypto.getRandomValues(new Uint8Array(1))[0]!;
    if (byte < 248) id += alphabet[byte % 62];
  }
  return id;
}

const knownIds = new WeakMap<object, string>();

/**
 * The WorkPass client id of this deployment: random, created once, kept in the
 * database. Reads never create it; the migration does (ensureWorkPassClient).
 */
export async function workpassClientId(env: Env): Promise<string> {
  const cached = knownIds.get(env.DB);
  if (cached) return cached;
  const row = await env.DB.prepare("SELECT value FROM app_settings WHERE key = ?")
    .bind(CLIENT_ID_KEY).first<{ value: string }>().catch(() => null);
  // Before the first migration there is nothing to sign in to; the legacy id
  // keeps unmigrated tooling and old test databases working.
  if (!row) return LEGACY_WORKPASS_CLIENT_ID;
  knownIds.set(env.DB, row.value);
  return row.value;
}

/** Create the id on the first migration. Safe to run again and from concurrent workers. */
async function ensureClientIdValue(env: Env): Promise<string> {
  const existing = await env.DB.prepare("SELECT value FROM app_settings WHERE key = ?")
    .bind(CLIENT_ID_KEY).first<{ value: string }>();
  if (existing) return existing.value;
  await env.DB.prepare(
    "INSERT OR IGNORE INTO app_settings (key, value, updated_by, updated_at) VALUES (?, ?, 'system', ?)",
  ).bind(CLIENT_ID_KEY, randomClientId(), new Date().toISOString()).run();
  const stored = await env.DB.prepare("SELECT value FROM app_settings WHERE key = ?")
    .bind(CLIENT_ID_KEY).first<{ value: string }>();
  return stored!.value;
}

/** Tables whose rows name the client, as the bare id or as `oidc:<id>`. */
const CLIENT_ID_COLUMNS = [
  ["oauthAccessToken", "clientId"],
  ["oauthRefreshToken", "clientId"],
  ["oauthConsent", "clientId"],
  ["oauthClientResource", "clientId"],
  ["oauth_device_grants", "client_id"],
  ["oauth_ciba_requests", "client_id"],
  ["applications", "binding"],
] as const;
const CLIENT_SUBJECT_TABLES = [
  "app_access_policies",
  "app_policy_groups",
  "app_issuance_history",
  "claim_release_policies",
  "app_temporal_grants",
  "access_requests",
  "request_rule_bindings",
] as const;

async function tableExists(env: Env, name: string): Promise<boolean> {
  return (await env.DB.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(name).first()) !== null;
}

/** Move everything that pointed at the old fixed id to the new one. */
async function renameClientEverywhere(env: Env, from: string, to: string): Promise<void> {
  const statements: D1PreparedStatement[] = [];
  statements.push(env.DB.prepare('UPDATE "oauthClient" SET clientId = ? WHERE clientId = ?').bind(to, from));
  for (const [table, column] of CLIENT_ID_COLUMNS) {
    if (await tableExists(env, table)) {
      statements.push(env.DB.prepare(`UPDATE "${table}" SET "${column}" = ? WHERE "${column}" = ?`).bind(to, from));
    }
  }
  for (const table of CLIENT_SUBJECT_TABLES) {
    if (await tableExists(env, table)) {
      statements.push(env.DB.prepare(`UPDATE "${table}" SET subject = ? WHERE subject = ?`).bind(`oidc:${to}`, `oidc:${from}`));
    }
  }
  await env.DB.batch(statements);
}

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

  const clientId = await ensureClientIdValue(env);
  knownIds.set(env.DB, clientId);
  // A deployment that still has the old fixed id gets it renamed, with every
  // token, policy and history row that referred to it.
  const legacy = await env.DB.prepare('SELECT id FROM "oauthClient" WHERE clientId = ?')
    .bind(LEGACY_WORKPASS_CLIENT_ID).first<{ id: string }>();
  const current = await env.DB.prepare('SELECT id FROM "oauthClient" WHERE clientId = ?')
    .bind(clientId).first<{ id: string }>();
  if (legacy && !current) await renameClientEverywhere(env, LEGACY_WORKPASS_CLIENT_ID, clientId);

  const now = new Date().toISOString();
  const scopes = JSON.stringify(["openid", "profile", "email", ...WORKPASS_SCOPES]);
  const redirectUris = JSON.stringify([workpassRedirectUri(env)]);
  const existing = await env.DB.prepare('SELECT id FROM "oauthClient" WHERE clientId = ?')
    .bind(clientId).first<{ id: string }>();

  if (existing) {
    await env.DB.prepare(
      `UPDATE "oauthClient" SET name = ?, redirectUris = ?, scopes = ?, grantTypes = ?, responseTypes = ?,
         tokenEndpointAuthMethod = 'none', applicationType = 'web', skipConsent = 1, requirePKCE = 1,
         clientSecret = NULL, updatedAt = ? WHERE clientId = ?`,
    ).bind(
      WORKPASS_CLIENT_NAME, redirectUris, scopes,
      JSON.stringify(["authorization_code"]), JSON.stringify(["code"]), now, clientId,
    ).run();
    return;
  }

  await env.DB.prepare(
    `INSERT INTO "oauthClient"
       (id, clientId, name, redirectUris, scopes, grantTypes, responseTypes, tokenEndpointAuthMethod,
        applicationType, skipConsent, requirePKCE, disabled, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'none', 'web', 1, 1, 0, ?, ?)`,
  ).bind(
    crypto.randomUUID(), clientId, WORKPASS_CLIENT_NAME, redirectUris, scopes,
    JSON.stringify(["authorization_code"]), JSON.stringify(["code"]), now, now,
  ).run();
}

/** The registry row that lists the dashboard next to every other app. */
export async function ensureWorkPassApplication(env: Env): Promise<void> {
  const clientId = await workpassClientId(env);
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
    clientId, launchUrl, now, now,
  ).run();
}
