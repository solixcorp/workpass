/**
 * OPAQUE endpoints (RFC 9807): the ONLY credential path where the wire
 * carries zero password material. The password never leaves the client and
 * the server stores no password, no hash, and no password-derived value —
 * only a password-protected credential record (sealed at rest).
 *
 * Registration is session-bound (the signed-in user enrolls their own
 * record); login is public, rate-limited, single-transcript, and resistant
 * to user enumeration. Success issues a genuine Better Auth session with
 * the exact same signed cookie as the password sign-in.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { createAuth } from "./config";
import {
  base64Decode,
  base64Encode,
  opaqueBadRequest,
  opaqueConfig,
  opaqueIdentityFor,
  opaqueServer,
} from "./opaque";
import { sealString, unsealString } from "../crypto/sealed";
import { insertAuditEvent } from "../audit/store";
import { recordLogin } from "../users/login-history";
import { locationGate, notifyLocationDenied } from "../security/location-gate";
import { auditStandaloneOperation } from "../audit/store";
import { evaluateOpaqueLoginGate } from "./opaque-login";
import { getStepUpChallenge, openStepUpChallenge, usableSecondFactors } from "../security/step-up";
import { stepUpUi } from "../security/step-up-ui";
import { loginRequiresSecondFactor } from "../mfa/policy";

export const opaqueRoutes = new Hono<{ Bindings: Env }>();

const TRANSCRIPT_TTL_MS = 2 * 60 * 1000;

interface AuthContext {
  secret: string;
  sessionTokenCookieName: string;
  secureCookie: boolean;
  createSession: (userId: string, device?: { ipAddress?: string; userAgent?: string }) => Promise<{ token: string } | null>;
}

async function authContext(env: Env): Promise<AuthContext> {
  const auth = createAuth(env);
  const context = await (auth as unknown as {
    $context: Promise<{
      secret: string;
      session?: { expiresIn?: number };
      authCookies: Record<string, { name: string; attributes: Record<string, unknown> }>;
      internalAdapter: {
        createSession(
          userId: string,
          dontRememberMe?: boolean,
          override?: Record<string, unknown>,
          overrideAll?: boolean,
        ): Promise<{ token: string; user: { name: string; email: string } } & Record<string, unknown> | null>;
      };
    }>;
  }).$context;
  const sessionCookie = context.authCookies.sessionToken as { name: string; attributes: Record<string, unknown> };
  return {
    secret: context.secret as unknown as string,
    sessionTokenCookieName: sessionCookie.name,
    secureCookie: sessionCookie.name.startsWith("__Secure-"),
    createSession: async (userId, device) =>
      await context.internalAdapter.createSession(userId, false, device ? { ...device } : undefined),
  };
}

/** Replicate Better Auth's signed session cookie (HMAC-SHA256 value.signature). */
async function sessionCookieHeader(
  context: Context<{ Bindings: Env }>,
  auth: AuthContext,
  token: string,
): Promise<string> {
  const encodedSecret = new TextEncoder().encode(auth.secret);
  const key = await crypto.subtle.importKey("raw", encodedSecret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token)));
  let base64 = "";
  for (const byte of signature) base64 += String.fromCharCode(byte);
  const value = JSON.parse(JSON.stringify({
    signed: encodeURIComponent(`${token}.${btoa(base64)}`),
  })) as { signed: string };
  const parts = [
    `${auth.sessionTokenCookieName}=${value.signed}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${60 * 60 * 24 * 7}`,
  ];
  if (auth.secureCookie) parts.push("Secure");
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// Wire helpers: opaque messages travel as base64url strings inside JSON.
// ---------------------------------------------------------------------------

const WIRE_PATTERN = /^[A-Za-z0-9_-]{1,4096}$/;

/** OPAQUE JSON fields are base64url strings (1–4096 chars). */
export function wireToBase64(value: unknown): string {
  if (typeof value !== "string" || !WIRE_PATTERN.test(value)) {
    throw new Error("Malformed OPAQUE message");
  }
  return value;
}

function wireFromNumberArray(value: unknown): string {
  if (!Array.isArray(value) || !value.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)) {
    throw new Error("Malformed OPAQUE message");
  }
  return base64Encode(Uint8Array.from(value as number[]));
}

async function requireSession(context: Context<{ Bindings: Env }>) {
  return await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
}

export async function storeCredentialRecord(env: Env, userId: string, identity: string, recordBytes: Uint8Array): Promise<void> {
  const sealed = await sealString(env, JSON.stringify(Array.from(recordBytes)), `opaque_record:${userId}`);
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO opaque_credential_records (user_id, record, credential_identifier, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (user_id) DO UPDATE SET record = excluded.record,
       credential_identifier = excluded.credential_identifier, updated_at = excluded.updated_at`,
  ).bind(userId, sealed, identity, now, now).run();
}

async function loadCredentialRecord(
  env: Env,
  userId: string,
): Promise<{ identity: string; record: Uint8Array } | null> {
  const row = await env.DB.prepare(
    "SELECT record, credential_identifier FROM opaque_credential_records WHERE user_id = ?",
  ).bind(userId).first<{ record: string; credential_identifier: string }>().catch(() => null);
  if (!row) return null;
  const plaintext = await unsealString(env, row.record, `opaque_record:${userId}`);
  const parsed = JSON.parse(plaintext) as unknown;
  const recordWire = typeof parsed === "string"
    ? parsed
    : Array.isArray(parsed)
      ? base64Encode(Uint8Array.from(parsed as number[]))
      : "";
  return { identity: row.credential_identifier, record: base64Decode(recordWire) };
}

async function lookupUser(
  env: Env,
  username: string,
): Promise<{ id: string; email: string } | null> {
  const normalized = username.trim().toLowerCase();
  if (!normalized || normalized.length > 256) return null;
  const row = await env.DB.prepare(
    `SELECT id, email FROM "user" WHERE lower(username) = ? OR lower(email) = ? LIMIT 1`,
  ).bind(normalized, normalized).first<{ id: string; email: string }>().catch(() => null);
  return row ?? null;
}

export async function rateBucket(env: Env, ip: string): Promise<boolean> {
  const nowMinute = Math.floor(Date.now() / 60_000);
  const result = await env.DB.prepare(
    `INSERT INTO fingerprint_lookup_limits (budget_key, window_start, request_count)
     VALUES (?, ?, 1)
     ON CONFLICT(budget_key) DO UPDATE SET
       request_count = CASE
         WHEN fingerprint_lookup_limits.window_start = excluded.window_start
         THEN fingerprint_lookup_limits.request_count + 1
         ELSE 1
       END,
       window_start = excluded.window_start
     RETURNING request_count`,
  ).bind(`opaque_login:${ip}`, nowMinute).first<{ request_count: number }>();
  return (result?.request_count ?? Number.POSITIVE_INFINITY) <= 30;
}

export function clientIp(context: Context<{ Bindings: Env }>): string {
  return context.req.header("cf-connecting-ip")
    ?? context.req.header("x-forwarded-for")?.split(",")[0]?.trim()
    ?? "127.0.0.1";
}

// ---------------------------------------------------------------------------
// Registration (session-bound enrollment of the acting user)
// ---------------------------------------------------------------------------

opaqueRoutes.post("/api/opaque/register/start", async (context) => {
  const session = await requireSession(context);
  if (!session) return opaqueBadRequest(context, "OPAQUE registration requires a session", 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return opaqueBadRequest(context, "The OPAQUE registration could not be processed"); }
  const value = (body ?? {}) as Record<string, unknown>;
  let wire: string;
  try { wire = wireToBase64(value.registrationRequest); } catch { return opaqueBadRequest(context, "The OPAQUE registration could not be processed"); }

  const config = opaqueConfig();
  const { RegistrationRequest, RegistrationRecord } = await import("@cloudflare/opaque-ts");
  const identity = opaqueIdentityFor(session.user.email);
  const { server } = await opaqueServer(context.env);
  const request = RegistrationRequest.deserialize(config, Array.from(base64Decode(wire)));
  const response = await server.registerInit(request, identity);
  if (response instanceof Error) return opaqueBadRequest(context, "The OPAQUE registration could not be processed");

  return auditStandaloneOperation(context.env, "opaque.register.start", "/api/opaque/register/start", async () => ({
    response: Response.json({
      registrationResponse: base64Encode(new Uint8Array(response.serialize())),
      credentialIdentifier: identity,
      serverIdentity: new URL(context.env.AUTH_BASE_URL).origin,
    }),
    actorUserId: session.user.id,
  }));
});

opaqueRoutes.post("/api/opaque/register/finish", async (context) => {
  const session = await requireSession(context);
  if (!session) return opaqueBadRequest(context, "OPAQUE registration requires a session", 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return opaqueBadRequest(context, "The OPAQUE registration could not be processed"); }
  const value = (body ?? {}) as Record<string, unknown>;
  let recordBytes: Uint8Array;
  try { recordBytes = base64Decode(wireToBase64(value.record)); } catch { return opaqueBadRequest(context, "The OPAQUE registration could not be processed"); }
  try {
    // Validate the record parses before storing.
    const { RegistrationRecord } = await import("@cloudflare/opaque-ts");
    RegistrationRecord.deserialize(opaqueConfig(), Array.from(recordBytes));
  } catch {
    return opaqueBadRequest(context, "The OPAQUE registration could not be processed");
  }
  await storeCredentialRecord(context.env, session.user.id, opaqueIdentityFor(session.user.email), recordBytes);
  return auditStandaloneOperation(context.env, "opaque.register.finish", "/api/opaque/register/finish", async () => ({
    response: Response.json({ registered: true }, { status: 201 }),
    actorUserId: session.user.id,
  }));
});

// ---------------------------------------------------------------------------
// Login (public, zero-password)
// ---------------------------------------------------------------------------

opaqueRoutes.post("/api/opaque/auth/start", async (context) => {
  context.header("Cache-Control", "no-store");
  try {
  let body: unknown;
  try { body = await context.req.json(); } catch { return opaqueBadRequest(context, "The OPAQUE authentication could not be processed"); }
  const value = (body ?? {}) as Record<string, unknown>;
  const username = typeof value.username === "string" ? value.username.trim().toLowerCase() : "";
  let ke1Wire: string;
  try { ke1Wire = wireToBase64(value.ke1); } catch { return opaqueBadRequest(context, "The OPAQUE authentication could not be processed"); }
  // Device-risk contract: event ids only; a sealed result is explicitly
  // rejected, matching the password/username/passkey login endpoints.
  let fingerprintEventId: string | null = null;
  if (value.fingerprint !== undefined) {
    const fingerprint = (value.fingerprint ?? {}) as Record<string, unknown>;
    if (typeof fingerprint !== "object" || fingerprint.sealed_result !== undefined || value.sealed_result !== undefined) {
      return context.json({ error: "Sealed Fingerprint results are not configured; use event_id" }, { status: 400 });
    }
    if (typeof fingerprint.event_id === "string" && fingerprint.event_id.length >= 1 && fingerprint.event_id.length <= 256) {
      fingerprintEventId = fingerprint.event_id;
    }
  }
  if (!username || username.length > 256) {
    return opaqueBadRequest(context, "The OPAQUE authentication could not be processed");
  }
  if (!(await rateBucket(context.env, clientIp(context)))) {
    return context.json({ error: "Too many authentication attempts; retry later" }, 429);
  }

  const config = opaqueConfig();
  const { KE1, RegistrationRecord } = await import("@cloudflare/opaque-ts");
  const { server } = await opaqueServer(context.env);
  const serverIdentity = new URL(context.env.AUTH_BASE_URL).origin;

  const user = await lookupUser(context.env, username);
  const stored = user ? await loadCredentialRecord(context.env, user.id) : null;
  // Enumeration resistance: the transcript always binds the identifier the
  // caller typed, and the response echoes only that value. A real record is
  // used only when it was enrolled under exactly this identifier (the
  // lowercased email); an unknown identifier, an account without an OPAQUE
  // record, or a username entry gets a fake record, so the client-side proof
  // fails identically and no response field reveals whether the account exists.
  const usable = stored && stored.identity === username ? stored : null;
  const record = usable
    ? RegistrationRecord.deserialize(config, Array.from(usable.record))
    : await RegistrationRecord.createFake(config);

  const parsed = KE1.deserialize(config, Array.from(base64Decode(ke1Wire)));
  const init = await server.authInit(parsed, record, username, username);
  if (init instanceof Error) return opaqueBadRequest(context, "The OPAQUE authentication could not be processed");

  await context.env.DB.prepare("DELETE FROM opaque_login_transcripts WHERE expires_at < ?")
    .bind(new Date().toISOString()).run();
  const transcriptId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + TRANSCRIPT_TTL_MS).toISOString();
  await context.env.DB.prepare(
    `INSERT INTO opaque_login_transcripts (id, user_id, client_identity, expected, created_at, expires_at, fingerprint_event_id)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    transcriptId,
    usable ? user!.id : null,
    username,
    JSON.stringify(Array.from(init.expected.serialize())),
    new Date().toISOString(),
    expiresAt,
    fingerprintEventId,
  ).run();

  return Response.json({
    ke2: base64Encode(new Uint8Array(init.ke2.serialize())),
    credentialIdentifier: username,
    serverIdentity,
    transcriptId,
  });
  } catch (error) {
    console.error("opaque auth start failure", error instanceof Error ? error.message : String(error));
    return opaqueBadRequest(context, "The OPAQUE authentication could not be processed");
  }
});

opaqueRoutes.post("/api/opaque/auth/finish", async (context) => {
  context.header("Cache-Control", "no-store");
  let body: unknown;
  try { body = await context.req.json(); } catch { return opaqueBadRequest(context, "The OPAQUE authentication could not be processed"); }
  const value = (body ?? {}) as Record<string, unknown>;
  const username = typeof value.username === "string" ? value.username.trim().toLowerCase() : "";
  const transcriptId = typeof value.transcriptId === "string" && value.transcriptId.length <= 64 ? value.transcriptId : "";
  let ke3Bytes: Uint8Array;
  try { ke3Bytes = base64Decode(wireToBase64(value.ke3)); } catch { return opaqueBadRequest(context, "The OPAQUE authentication could not be processed"); }
  if (!(await rateBucket(context.env, clientIp(context)))) {
    return context.json({ error: "Too many authentication attempts; retry later" }, 429);
  }

  if (!transcriptId || !username) return opaqueBadRequest(context, "The OPAQUE authentication could not be processed", 401);
  const transcriptRow = await context.env.DB.prepare(
    `DELETE FROM opaque_login_transcripts WHERE id = ? AND expires_at > ?
     RETURNING user_id, client_identity, expected, fingerprint_event_id`,
  ).bind(transcriptId, new Date().toISOString()).first<{ user_id: string; client_identity: string; expected: string; fingerprint_event_id: string | null }>().catch(() => null);
  if (!transcriptRow || !transcriptRow.user_id) {
    return opaqueBadRequest(context, "The OPAQUE authentication could not be processed", 401);
  }

  const config = opaqueConfig();
  const { KE3, ExpectedAuthResult } = await import("@cloudflare/opaque-ts");
  const { server } = await opaqueServer(context.env);
  let finish: ReturnType<typeof server.authFinish>;
  try {
    const expected = ExpectedAuthResult.deserialize(config, JSON.parse(transcriptRow.expected) as number[]);
    finish = server.authFinish(KE3.deserialize(config, Array.from(ke3Bytes)), expected);
  } catch {
    // A malformed KE3 must look exactly like a failed proof (401), never a 500
    // that would distinguish a real account's transcript from an unknown one.
    finish = new Error("Malformed OPAQUE message");
  }
  if (finish instanceof Error) {
    return opaqueBadRequest(context, "The OPAQUE authentication could not be processed", 401);
  }

  // The login gate: account state plus the shared device-risk pipeline, run
  // after the cryptography succeeds and before any session issues. Denials
  // are indistinguishable to the caller.
  const gate = await evaluateOpaqueLoginGate(context.env, {
    userId: transcriptRow.user_id,
    eventId: transcriptRow.fingerprint_event_id,
    request: context.req.raw,
    contextPath: "/api/opaque/auth/finish",
  });
  if (!gate.allowed) {
    try {
      await insertAuditEvent(context.env, {
        id: crypto.randomUUID(),
        actor_user_id: transcriptRow.user_id,
        target_user_id: transcriptRow.user_id,
        event_type: "authentication.opaque.login",
        outcome: "failure",
        request_path: "/api/opaque/auth/finish",
      });
    } catch {
      // The denial stands regardless; the audit gap is visible in logs.
    }
    return opaqueBadRequest(context, "The OPAQUE authentication could not be processed", 403);
  }

  // Where the sign-in comes from: after the proof succeeded, so the reason may be named.
  const place = await locationGate(context.env, { request: context.req.raw, userId: transcriptRow.user_id, path: "/api/opaque/auth/finish" });
  if (!place.allowed) {
    await notifyLocationDenied(context.env, transcriptRow.user_id);
    return context.json({ error: "Sign-in is not allowed from this location", code: "location_denied" }, 403);
  }

  const auth = await authContext(context.env);
  const userAgent = context.req.header("user-agent");
  const session = await auth.createSession(transcriptRow.user_id, {
    ipAddress: clientIp(context),
    ...(userAgent ? { userAgent: userAgent.slice(0, 512) } : {}),
  });
  if (!session) return opaqueBadRequest(context, "The OPAQUE authentication could not be processed", 503);

  // Step-up challenge: the gate allowed the login under a step_up decision
  // because the account has an enrollable second factor; SSO issuance stays
  // withheld until it is verified. Opening the row failing is fail-closed.
  let stepUpAnnotation: { methods: string[]; expiresAt: string | null; reasons: string[] } | null = null;
  // A required second factor the account already has is asked for right here.
  const mfaRequiredNow = gate.action !== "step_up" && await loginRequiresSecondFactor(context.env, transcriptRow.user_id).catch(() => false);
  if (gate.action === "step_up" || mfaRequiredNow) {
    const methods = await usableSecondFactors(context.env, transcriptRow.user_id).catch(() => [] as string[]);
    const opened = methods.length > 0 &&
      await openStepUpChallenge({
        env: context.env,
        sessionToken: session.token,
        userId: transcriptRow.user_id,
        reasons: mfaRequiredNow ? ["mfa_required"] : gate.reasons.slice(0, 5),
        requestPath: "/api/opaque/auth/finish",
      }).catch(() => false);
    if (!opened) {
      await context.env.DB.prepare('DELETE FROM "session" WHERE token = ?').bind(session.token).run().catch(() => {});
      await insertAuditEvent(context.env, {
        id: crypto.randomUUID(),
        actor_user_id: transcriptRow.user_id,
        target_user_id: transcriptRow.user_id,
        event_type: "authentication.opaque.login",
        outcome: "failure",
        request_path: "/api/opaque/auth/finish",
        client_ip: clientIp(context),
      }).catch(() => {});
      return opaqueBadRequest(context, "The OPAQUE authentication could not be processed", 503);
    }
    const challenge = await getStepUpChallenge(context.env, session.token);
    stepUpAnnotation = { methods, expiresAt: challenge.expiresAt, reasons: challenge.reasons };
  }

  const cookie = await sessionCookieHeader(context, auth, session.token);
  await insertAuditEvent(context.env, {
    id: crypto.randomUUID(),
    actor_user_id: transcriptRow.user_id,
    target_user_id: transcriptRow.user_id,
    event_type: "authentication.opaque.login",
    outcome: "success",
    request_path: "/api/opaque/auth/finish",
    client_ip: clientIp(context),
  });
  await recordLogin(context.env, context.req.raw, transcriptRow.user_id, "password");
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    "Set-Cookie": cookie,
  });
  const responseBody: Record<string, unknown> = { token: session.token };
  if (stepUpAnnotation) {
    responseBody.stepUpChallenge = { required: true, ...stepUpAnnotation, ui: stepUpUi(stepUpAnnotation.methods, stepUpAnnotation.reasons) };
  }
  return new Response(JSON.stringify(responseBody), { status: 200, headers });
});
