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
import type { PolicyEvaluationContext } from "./types";
import {
  enforcePasswordEntry,
  evaluateLoginSurface,
  recordSuccessfulPasswordWrite,
} from "./password-entry";
import { recordReputationOutcome } from "./reputation";

interface HookPayload {
  path: string;
  body: Record<string, unknown> | null;
  headers: Headers | undefined;
  session?: { user?: { id?: string } | null } | null;
  user?: { id?: string } | null;
  request?: Request;
  returned?: Response;
}

function geoFromRequest(request: Request | undefined): NonNullable<PolicyEvaluationContext["geo"]> | undefined {
  const cf = (request as (Request & { cf?: Record<string, unknown> }) | undefined)?.cf;
  if (!cf || typeof cf !== "object") return undefined;
  const geo: Record<string, unknown> = {};
  if (typeof cf.country === "string") geo.country = cf.country;
  if (typeof cf.city === "string") geo.city = cf.city;
  if (typeof cf.latitude === "number") geo.lat = cf.latitude;
  if (typeof cf.longitude === "number") geo.long = cf.longitude;
  if (typeof cf.asn === "number") geo.asn = cf.asn;
  if (typeof cf.asOrganization === "string") geo.asOrg = cf.asOrganization;
  return Object.keys(geo).length > 0 ? (geo as NonNullable<PolicyEvaluationContext["geo"]>) : undefined;
}

function readContext(hookContext: unknown): HookPayload {
  const value = (hookContext ?? {}) as {
    path?: string;
    body?: Record<string, unknown> | null;
    headers?: Headers;
    session?: { user?: { id?: string } | null } | null;
    user?: { id?: string } | null;
    request?: Request;
    returned?: Response;
    context?: {
      session?: { user?: { id?: string } | null } | null;
      user?: { id?: string } | null;
      request?: Request;
      returned?: Response;
    } | null;
  };
  const session = value.context?.session ?? value.session;
  const user = value.context?.user ?? value.user;
  const request = value.context?.request ?? value.request;
  const returned = value.context?.returned ?? value.returned;
  return {
    path: value.path ?? "",
    body: value.body ?? null,
    headers: value.headers,
    session,
    user,
    request,
    returned,
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

const LOGIN_PATHS = new Set(["/sign-in/email", "/sign-in/username", "/passkey/verify-authentication"]);

/** Password write paths better-auth serves directly. */
const PASSWORD_ENTRY_PATHS = new Set(["/change-password", "/set-password", "/admin/set-user-password", "/reset-password", "/admin/create-user", "/sign-up/email"]);
const PASSWORD_LOGIN_PATHS = new Set(["/sign-in/email", "/sign-in/username"]);
/** Paths whose successful responses complete a password change. */
const PASSWORD_SUCCESS_PATHS = new Set(["/change-password", "/set-password", "/admin/set-user-password", "/reset-password"]);

const AFTER_RESULT = { headers: undefined, response: undefined } as {
  headers: Headers | undefined;
  response: Response | undefined;
};

export function createPasswordPolicyHooks(env: Env): {
  before: (hookContext: unknown) => Promise<unknown>;
  after: (hookContext: unknown) => Promise<unknown>;
} {
  const before = async (hookContext: unknown): Promise<unknown> => {
    const { path, body, headers, user: hookUser, session: hookSession, request } = readContext(hookContext);
    const actingOrTargetUser = hookUser ?? hookSession?.user ?? undefined;

    if (PASSWORD_ENTRY_PATHS.has(path)) {
      const password = pickPassword(body);
      if (!password) return undefined; // No password in this request; nothing to validate.
      const userId = path === "/admin/create-user" || path === "/sign-up/email"
        ? null : pickTargetUser(body, actingOrTargetUser);
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
      const outcome = await evaluateLoginSurface(env, userId, {
        clientIp: clientIp(headers),
        requestPath: path,
        geo: geoFromRequest(request),
      });
      if (!outcome.passing) reject(outcome.messages);
      return undefined;
    }

    return undefined;
  };

  const after = async (hookContext: unknown): Promise<unknown> => {
    const { path, body, headers, user: hookUser, session: hookSession, request, returned } = readContext(hookContext);
    if (!PASSWORD_SUCCESS_PATHS.has(path)) {
      // Reputation accounting for login outcomes (failures decrement, success
      // increments); the response status is the source of truth.
      if (LOGIN_PATHS.has(path)) {
        const identity = typeof body?.email === "string"
          ? body.email
          : typeof body?.username === "string" ? body.username : null;
        const status = returned?.status ?? 200;
        await recordReputationOutcome(env, clientIp(headers), identity, status === 200)
          .catch(() => undefined);
      }
      return AFTER_RESULT;
    }
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
