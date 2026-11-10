/**
 * Password-entry enforcement (docs/design/authentik-policies.md): a single
 * surface helper that password writes call before accepting a candidate, and
 * a login-surface gate that login pipelines call before issuing sessions.
 * Both run the ordered binding engine; failures carry user-visible messages.
 */

import type { Env } from "../env";
import { evaluateBoundPolicies, loadUserSnapshot } from "./engine";
import { getPasswordMeta } from "./password";
import type { PolicyEvaluationContext } from "./types";
import { passwordHistoryAppend, recordPasswordChange } from "./password";

export class PasswordPolicyViolation extends Error {
  readonly messages: string[];
  constructor(messages: string[]) {
    super(messages.join("; "));
    this.messages = messages;
  }
}

export interface PasswordEntryRuntime {
  clientIp?: string | null;
  context?: Record<string, unknown>;
  requestPath?: string;
}

/**
 * Run every policy bound to the password_entry surface for this user. The
 * candidate password is placed in the context (`ctx.password`) so `password`,
 * `password_uniqueness` (and any expression) can read it. An empty binding
 * set passes — complexity rules apply only where an operator bound them.
 */
export async function enforcePasswordEntry(
  env: Env,
  userId: string | null,
  password: string,
  runtime: PasswordEntryRuntime = {},
): Promise<{ passing: boolean; messages: string[] }> {
  const user = userId ? await loadUserSnapshot(env, userId) : null;
  return await evaluateBoundPolicies(env, "password_entry", PASSWORD_ENTRY_REF, {
    user,
    clientIp: runtime.clientIp ?? null,
    subject: null,
    password,
    context: runtime.context ?? {},
    requestPath: runtime.requestPath,
  } satisfies PolicyEvaluationContext);
}

/** The global password-entry reference; bindings target "" for all writes. */
export const PASSWORD_ENTRY_REF = "";

/**
 * Record a successful password write: refresh the change timestamp, clear the
 * unusable flag, and append the reuse-history digest.
 */
export async function recordSuccessfulPasswordWrite(env: Env, userId: string, password: string): Promise<void> {
  await recordPasswordChange(env, userId);
  await passwordHistoryAppend(env, userId, password);
}

/**
 * The login-surface gate: expiry (which may mark the password unusable) and
 * all other bound login policies evaluate here. Throwing with the collected
 * messages is the caller's choice; the function only reports.
 */
export async function evaluateLoginSurface(
  env: Env,
  userId: string,
  runtime: PasswordEntryRuntime = {},
): Promise<{ passing: boolean; messages: string[] }> {
  const meta = userId ? await getPasswordMeta(env, userId) : null;
  if (meta?.unusable) {
    return { passing: false, messages: ["the password is unusable; set a new one before signing in"] };
  }
  const user = userId ? await loadUserSnapshot(env, userId) : null;
  return await evaluateBoundPolicies(env, "login", LOGIN_SURFACE_REF, {
    user,
    clientIp: runtime.clientIp ?? null,
    subject: null,
    context: runtime.context ?? {},
    requestPath: runtime.requestPath,
  } satisfies PolicyEvaluationContext);
}

/** The global login-surface reference; bindings target "" for all pipelines. */
export const LOGIN_SURFACE_REF = "";

