import type { Env } from "../env";
import { digestVisitorId } from "./fingerprint";
import { PASSWORD_ENTRY_REF } from "../policies/password-entry";
import { validatePasswordConfig, type PasswordPolicyConfig } from "../policies/password";
import { applySettings } from "../settings/store";

/**
 * Account activation: the first-time (or reset) password setup for an account
 * that has no OPAQUE credential yet. An administrator issues a one-time link;
 * the user opens it, the browser runs the OPAQUE registration with the token
 * as authorization, and the token is consumed. Activation never signs the user
 * in: the normal login (device risk, second factor) runs afterwards.
 *
 * The token is 256 random bits; only its keyed digest is stored. Expired,
 * used and unknown tokens are indistinguishable to the caller.
 */

export const ACTIVATION_PURPOSE = "account-activation";

export interface ActivationLink {
  token: string;
  expiresAt: string;
}

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{40,128}$/;

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function isWellFormedToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

export async function activationTtlMinutes(env: Env): Promise<number> {
  const effective = await applySettings(env);
  const raw = Number(effective.ACTIVATION_TOKEN_TTL_MINUTES);
  return Number.isInteger(raw) && raw >= 5 && raw <= 4320 ? raw : 1440;
}

export function activationUrl(env: Env, token: string): string {
  return `${new URL(env.AUTH_BASE_URL).origin}/activate#${token}`;
}

/** Issue a link, replacing any still-open link for the same user. */
export async function issueActivationLink(input: {
  env: Env;
  userId: string;
  actorUserId: string;
  deliveredTo?: string | null;
}): Promise<ActivationLink> {
  const ttl = await activationTtlMinutes(input.env);
  const now = Date.now();
  const expiresAt = new Date(now + ttl * 60_000).toISOString();
  const token = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await digestVisitorId(input.env, `${ACTIVATION_PURPOSE}:${token}`);
  await input.env.DB.batch([
    input.env.DB.prepare(
      "UPDATE account_activation_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
    ).bind(new Date(now).toISOString(), input.userId),
    input.env.DB.prepare(
      `INSERT INTO account_activation_tokens
         (id, user_id, token_digest, created_by, created_at, expires_at, used_at, delivered_to, delivered_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL)`,
    ).bind(
      crypto.randomUUID(), input.userId, digest, input.actorUserId,
      new Date(now).toISOString(), expiresAt, input.deliveredTo ?? null,
    ),
  ]);
  return { token, expiresAt };
}

export async function markActivationDelivered(env: Env, token: string): Promise<void> {
  const digest = await digestVisitorId(env, `${ACTIVATION_PURPOSE}:${token}`);
  await env.DB.prepare(
    "UPDATE account_activation_tokens SET delivered_at = ? WHERE token_digest = ?",
  ).bind(new Date().toISOString(), digest).run();
}

export interface OpenActivation {
  id: string;
  userId: string;
  email: string;
  expiresAt: string;
}

/** The live link for a token, or null for anything else (no distinction). */
export async function findOpenActivation(env: Env, token: unknown): Promise<OpenActivation | null> {
  if (!isWellFormedToken(token)) return null;
  const digest = await digestVisitorId(env, `${ACTIVATION_PURPOSE}:${token}`);
  const row = await env.DB.prepare(
    `SELECT t.id AS id, t.user_id AS userId, t.expires_at AS expiresAt, u.email AS email
     FROM account_activation_tokens t JOIN "user" u ON u.id = t.user_id
     WHERE t.token_digest = ? AND t.used_at IS NULL AND t.expires_at > ? LIMIT 1`,
  ).bind(digest, new Date().toISOString()).first<OpenActivation>();
  return row ?? null;
}

/**
 * Consume the link and revoke what the old credential could still reach.
 * Returns false when the link was already used or expired in the meantime.
 */
export async function consumeActivation(env: Env, link: OpenActivation): Promise<boolean> {
  const now = new Date().toISOString();
  const consumed = await env.DB.prepare(
    "UPDATE account_activation_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?",
  ).bind(now, link.id, now).run();
  if (consumed.meta.changes !== 1) return false;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM "session" WHERE "userId" = ?').bind(link.userId),
    env.DB.prepare("UPDATE trusted_devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, link.userId),
  ]);
  return true;
}

export async function cleanupActivationTokens(env: Env, now: Date): Promise<void> {
  const before = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM account_activation_tokens WHERE used_at IS NOT NULL AND used_at < ?").bind(before),
    env.DB.prepare("DELETE FROM account_activation_tokens WHERE used_at IS NULL AND expires_at < ?").bind(before),
  ]);
}

// --- password rules ---------------------------------------------------------

export interface PasswordRules {
  minLength: number;
  minUpper: number;
  minLower: number;
  minDigit: number;
  minSymbol: number;
  symbolSet: string;
  checkHibp: boolean;
}

/**
 * The rules the admin configured for password entry: every enabled `password`
 * policy bound to the password-entry surface, merged by taking the strictest
 * value. OPAQUE keeps the password away from the server, so these rules are
 * delivered to the browser, which checks them before registering.
 */
export async function activeAndBoundPasswordRules(env: Env): Promise<PasswordRules> {
  const rows = await env.DB.prepare(
    `SELECT p.config AS config
     FROM policy_bindings b JOIN policies p ON p.id = b.policy_id
     WHERE b.target = 'password_entry' AND b.target_ref = ? AND b.enabled = 1
       AND p.enabled = 1 AND p.type = 'password'
     LIMIT 20`,
  ).bind(PASSWORD_ENTRY_REF).all<{ config: string }>().catch(() => ({ results: [] as Array<{ config: string }> }));

  const configs: PasswordPolicyConfig[] = [];
  for (const row of rows.results) {
    try {
      configs.push(validatePasswordConfig(JSON.parse(row.config)));
    } catch {
      // A malformed policy is ignored here; the policy admin API rejects it on save.
    }
  }
  if (configs.length === 0) configs.push(validatePasswordConfig({}));
  return {
    minLength: Math.max(...configs.map((config) => config.minLength)),
    minUpper: Math.max(...configs.map((config) => config.minUpper)),
    minLower: Math.max(...configs.map((config) => config.minLower)),
    minDigit: Math.max(...configs.map((config) => config.minDigit)),
    minSymbol: Math.max(...configs.map((config) => config.minSymbol)),
    symbolSet: configs.find((config) => config.minSymbol > 0)?.symbolSet ?? configs[0]!.symbolSet,
    checkHibp: configs.some((config) => config.checkHibp),
  };
}
