/**
 * better-auth server hooks bridging the policy framework onto the password
 * endpoints better-auth owns directly (change-password, admin/set-user-password,
 * reset-password) and the password login endpoints (sign-in/email,
 * sign-in/username). Defined inside createAuth so each hook closes over the
 * request-time env.
 *
 * Contract notes (better-auth dispatch):
 * - `before` handlers may return undefined (no modification) or throw an
 *   APIError to reject the request.
 * - `after` handlers MUST return an object; the dispatcher reads
 *   `result.headers` (guarded) and `result.response !== undefined` decides
 *   short-circuiting, so we return an inert `{ headers: undefined,
 *   response: undefined }` when we only recorded side effects.
 */

import { APIError } from "better-auth/api";
import type { Env } from "../env";
import {
  enforcePasswordEntry,
  evaluateLoginSurface,
  recordSuccessfulPasswordWrite,
} from "./password-entry";

interface HookPayload {
  path: string;
  body: Record<string, unknown> | null;
  headers: Headers | undefined;
  session?: { user?: { id?: string } | null } | null;
  user?: { id?: string } | null;
}

function readContext(hookContext: unknown): HookPayload {
  const value = (hookContext ?? {}) as {
    path?: string;
    body?: Record<string, unknown> | null;
    headers?: Headers;
    context?: {
      session?: { user?: { id?: string } | null } | null;
      user?: { id?: string } | null;
    } | null;
  };
  return {
    path: value.path ?? "",
    body: value.body ?? null,
    headers: value.headers,
    session: value.context?.session,
    user: value.context?.user,
  };
}

function clientIp(headers: Headers | undefined): string | null {
  return headers?.get("cf-connecting-ip") ?? null;
}

function pickPassword(body: Record<string, unknown> | null | undefined): string | null {
  if (!body) return null;
  for (const candidate of [body.newPassword, body.new_password, body.password]) {
    if (typeof candidate === "string" && candidate.length > 0) return candidate;
  }
  return null;
}

/** On admin surfaces the target user comes from the body or params. */
function pickTargetUser(body: Record<string, unknown> | null | undefined, actor?: unknown): string | null {
  if (body) {
    if (typeof body.userId === "string" && body.userId) return body.userId;
    if (typeof body.params === "object" && body.params !== null) {
      const params = body.params as Record<string, unknown>;
      if (typeof params.userId === "string" && params.userId) return params.userId;
    }
    if (typeof body.user === "object" && body.user !== null && typeof (body.user as { id?: unknown }).id === "string") {
      return (body.user as { id: string }).id;
    }
  }
  if (typeof actor === "object" && actor !== null && typeof (actor as { id?: unknown }).id === "string") {
    return (actor as { id: string }).id;
  }
  return null;
}

function reject(messages: string[]): never {
  throw new APIError("FORBIDDEN", { message: messages.join("; ") });
}

/** Password write paths better-auth serves directly. */
const PASSWORD_ENTRY_PATHS = new Set(["/change-password", "/admin/set-user-password", "/reset-password"]);
const PASSWORD_LOGIN_PATHS = new Set(["/sign-in/email", "/sign-in/username"]);
/** Paths whose successful responses complete a password change. */
const PASSWORD_SUCCESS_PATHS = new Set(["/change-password", "/admin/set-user-password", "/reset-password"]);

const AFTER_RESULT = { headers: undefined, response: undefined } as {
  headers: Headers | undefined;
  response: Response | undefined;
};

export function createPasswordPolicyHooks(env: Env): {
  before: (hookContext: unknown) => Promise<unknown>;
  after: (hookContext: unknown) => Promise<unknown>;
} {
  const before = async (hookContext: unknown): Promise<unknown> => {
    const { path, body, headers, user: hookUser, session: hookSession } = readContext(hookContext);
    const actingOrTargetUser = hookUser ?? hookSession?.user ?? undefined;

    if (PASSWORD_ENTRY_PATHS.has(path)) {
      const password = pickPassword(body);
      if (!password) return undefined; // No password in this request; nothing to validate.
      const userId = pickTargetUser(body, actingOrTargetUser);
      const outcome = await enforcePasswordEntry(env, userId, password, { clientIp: clientIp(headers), requestPath: path });
      if (!outcome.passing) reject(outcome.messages);
      return undefined;
    }

    if (PASSWORD_LOGIN_PATHS.has(path)) {
      const identity = typeof body?.email === "string"
        ? body.email
        : typeof body?.username === "string" ? body.username : null;
      const userId = await resolveUserId(env, identity);
      if (!userId) return undefined; // Unknown identity: fall through to the login itself.
      const outcome = await evaluateLoginSurface(env, userId, { clientIp: clientIp(headers), requestPath: path });
      if (!outcome.passing) reject(outcome.messages);
      return undefined;
    }

    return undefined;
  };

  const after = async (hookContext: unknown): Promise<unknown> => {
    const { path, body, user: hookUser, session: hookSession } = readContext(hookContext);
    if (!PASSWORD_SUCCESS_PATHS.has(path)) return AFTER_RESULT;
    const password = pickPassword(body);
    const userId = pickTargetUser(body, hookUser ?? hookSession?.user ?? undefined);
    if (password && userId) {
      await recordSuccessfulPasswordWrite(env, userId, password).catch(() => undefined);
    }
    return AFTER_RESULT;
  };

  return { before, after };
}

async function resolveUserId(env: Env, identity: string | null): Promise<string | null> {
  if (!identity) return null;
  const byEmail = await env.DB.prepare('SELECT id FROM "user" WHERE email = ? LIMIT 1').bind(identity)
    .first<{ id: string }>();
  if (byEmail) return byEmail.id;
  const byUsername = await env.DB.prepare('SELECT id FROM "user" WHERE username = ? LIMIT 1').bind(identity)
    .first<{ id: string }>();
  return byUsername?.id ?? null;
}
