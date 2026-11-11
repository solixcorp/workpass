import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { createAuth } from "./config";
import { base64Decode, base64Encode, opaqueConfig, opaqueServer } from "./opaque";
import { wireToBase64 } from "./opaque-routes";
import { sealString, unsealString } from "../crypto/sealed";
import { activeAndBoundPasswordRules } from "../security/account-activation";
import { insertAuditEvent, updateAuditEvent } from "../audit/store";
import { appSessionSnapshot, logoutUserFromApps } from "../oauth/app-logout";
import { recordPasswordChange } from "../policies/password";

export const passwordChangeRoutes = new Hono<{ Bindings: Env }>();
const eventType = "identity.user.password_change.success_or_failure";
const prefix = "/api/me/password";

// This router must precede the better-auth catch-all in src/index.ts.
passwordChangeRoutes.use("/api/auth/*", async (c, next) => {
  if (c.env.ALLOW_PLAINTEXT_PASSWORD_LOGIN !== "true" && [
    "/api/auth/change-password", "/api/auth/set-password", "/api/auth/admin/set-user-password",
  ].includes(c.req.path)) return c.json({ error: "Not found" }, 404);
  await next();
});

type Ctx = Context<{ Bindings: Env }>;
type Actor = { userId: string; token: string; digest: string };

async function actor(c: Ctx): Promise<Actor | Response> {
  c.header("Cache-Control", "no-store");
  if (c.req.header("origin") !== new URL(c.env.AUTH_BASE_URL).origin) return c.json({ error: "Invalid origin" }, 403);
  const session = await createAuth(c.env).api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ error: "Unauthorized" }, 401);
  const digest = base64Encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(session.session.token))));
  return { userId: session.user.id, token: session.session.token, digest };
}

async function budget(c: Ctx, a: Actor, phase: "verify" | "register"): Promise<boolean> {
  const row = await c.env.DB.prepare(`INSERT INTO fingerprint_lookup_limits (budget_key, window_start, request_count)
    VALUES (?, ?, 1) ON CONFLICT(budget_key) DO UPDATE SET
    request_count = CASE WHEN window_start = excluded.window_start THEN request_count + 1 ELSE 1 END,
    window_start = excluded.window_start RETURNING request_count`)
    .bind(`password_change:${phase}:${a.userId}`, Math.floor(Date.now() / 60000)).first<{ request_count: number }>();
  return !!row && row.request_count <= 10;
}

async function input(c: Ctx): Promise<Record<string, unknown>> {
  try { const v = await c.req.json(); return v && typeof v === "object" && !Array.isArray(v) ? v : {}; } catch { return {}; }
}
async function audit(c: Ctx, a: Actor, outcome: "success" | "failure") {
  await insertAuditEvent(c.env, { id: crypto.randomUUID(), actor_user_id: a.userId, target_user_id: a.userId,
    event_type: eventType, outcome, request_path: c.req.path });
}
async function guard(c: Ctx, phase: "verify" | "register"): Promise<Actor | Response> {
  const a = await actor(c);
  if (a instanceof Response) return a;
  if (!(await budget(c, a, phase))) return c.json({ error: "Too many attempts" }, 429);
  return a;
}
async function confirmed(c: Ctx, a: Actor): Promise<boolean> {
  return !!await c.env.DB.prepare(`SELECT 1 FROM opaque_password_confirmations p JOIN opaque_credential_records r
    ON r.user_id = p.user_id AND r.record = p.record_snapshot
    WHERE p.user_id = ? AND p.session_digest = ? AND p.expires_at > ? AND p.claim IS NULL`)
    .bind(a.userId, a.digest, new Date().toISOString()).first();
}

passwordChangeRoutes.post(`${prefix}/verify-start`, async (c) => {
  const a = await guard(c, "verify"); if (a instanceof Response) return a;
  const b = await input(c);
  try {
    const row = await c.env.DB.prepare("SELECT record, credential_identifier FROM opaque_credential_records WHERE user_id = ?")
      .bind(a.userId).first<{ record: string; credential_identifier: string }>();
    if (!row) return c.json({ error: "No OPAQUE credential" }, 403);
    const { KE1, RegistrationRecord } = await import("@cloudflare/opaque-ts");
    const config = opaqueConfig();
    const plaintext = await unsealString(c.env, row.record, `opaque_record:${a.userId}`);
    const parsed = JSON.parse(plaintext) as number[] | string;
    const bytes = typeof parsed === "string" ? base64Decode(parsed) : Uint8Array.from(parsed);
    const record = RegistrationRecord.deserialize(config, Array.from(bytes));
    const ke1 = KE1.deserialize(config, Array.from(base64Decode(wireToBase64(b.ke1))));
    const { server } = await opaqueServer(c.env);
    const result = await server.authInit(ke1, record, row.credential_identifier, row.credential_identifier);
    if (result instanceof Error) throw result;
    const transcriptId = crypto.randomUUID();
    await c.env.DB.batch([
      c.env.DB.prepare("DELETE FROM opaque_password_change_transcripts WHERE expires_at <= ?").bind(new Date().toISOString()),
      c.env.DB.prepare("DELETE FROM opaque_password_confirmations WHERE expires_at <= ? OR (user_id = ? AND session_digest = ?)")
        .bind(new Date().toISOString(), a.userId, a.digest),
      c.env.DB.prepare(`INSERT INTO opaque_password_change_transcripts (id, user_id, session_digest, expected, record_snapshot, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)`).bind(transcriptId, a.userId, a.digest, JSON.stringify(result.expected.serialize()), row.record, new Date(Date.now() + 120000).toISOString()),
    ]);
    return c.json({ ke2: base64Encode(result.ke2.serialize()), credentialIdentifier: row.credential_identifier,
      serverIdentity: new URL(c.env.AUTH_BASE_URL).origin, transcriptId });
  } catch { return c.json({ error: "Invalid OPAQUE request" }, 400); }
});

passwordChangeRoutes.post(`${prefix}/verify-finish`, async (c) => {
  const a = await guard(c, "verify"); if (a instanceof Response) return a;
  const b = await input(c);
  const id = typeof b.transcriptId === "string" && b.transcriptId.length <= 64 ? b.transcriptId : "";
  const row = await c.env.DB.prepare(`DELETE FROM opaque_password_change_transcripts WHERE id = ? AND user_id = ?
    AND session_digest = ? AND expires_at > ? RETURNING expected, record_snapshot`)
    .bind(id, a.userId, a.digest, new Date().toISOString()).first<{ expected: string; record_snapshot: string }>();
  let valid = false;
  if (row) try {
    const { KE3, ExpectedAuthResult } = await import("@cloudflare/opaque-ts");
    const config = opaqueConfig(); const { server } = await opaqueServer(c.env);
    valid = !(server.authFinish(KE3.deserialize(config, Array.from(base64Decode(wireToBase64(b.ke3)))),
      ExpectedAuthResult.deserialize(config, JSON.parse(row.expected))) instanceof Error);
  } catch { valid = false; }
  if (!valid || !row) { await audit(c, a, "failure"); return c.json({ error: "Password confirmation failed" }, 401); }
  const expiresAt = new Date(Date.now() + 300000).toISOString();
  await c.env.DB.prepare(`INSERT INTO opaque_password_confirmations (user_id, session_digest, record_snapshot, expires_at, claim)
    VALUES (?, ?, ?, ?, NULL) ON CONFLICT(user_id, session_digest) DO UPDATE SET
    record_snapshot = excluded.record_snapshot, expires_at = excluded.expires_at, claim = NULL`)
    .bind(a.userId, a.digest, row.record_snapshot, expiresAt).run();
  return c.json({ confirmed: true, expiresAt, rules: await activeAndBoundPasswordRules(c.env) });
});

passwordChangeRoutes.post(`${prefix}/register-start`, async (c) => {
  const a = await guard(c, "register"); if (a instanceof Response) return a;
  if (!(await confirmed(c, a))) return c.json({ error: "Password confirmation required" }, 403);
  const b = await input(c);
  try {
    const row = await c.env.DB.prepare("SELECT credential_identifier FROM opaque_credential_records WHERE user_id = ?")
      .bind(a.userId).first<{ credential_identifier: string }>();
    if (!row) return c.json({ error: "Password confirmation required" }, 403);
    const { RegistrationRequest } = await import("@cloudflare/opaque-ts");
    const request = RegistrationRequest.deserialize(opaqueConfig(), Array.from(base64Decode(wireToBase64(b.registrationRequest))));
    const { server } = await opaqueServer(c.env); const response = await server.registerInit(request, row.credential_identifier);
    if (response instanceof Error) throw response;
    return c.json({ registrationResponse: base64Encode(response.serialize()), credentialIdentifier: row.credential_identifier,
      serverIdentity: new URL(c.env.AUTH_BASE_URL).origin });
  } catch { return c.json({ error: "Invalid OPAQUE request" }, 400); }
});

passwordChangeRoutes.post(`${prefix}/register-finish`, async (c) => {
  const a = await guard(c, "register"); if (a instanceof Response) return a;
  if (!(await confirmed(c, a))) { await audit(c, a, "failure"); return c.json({ error: "Password confirmation required" }, 403); }
  const b = await input(c); let bytes: Uint8Array;
  try {
    bytes = base64Decode(wireToBase64(b.record));
    const { RegistrationRecord } = await import("@cloudflare/opaque-ts");
    RegistrationRecord.deserialize(opaqueConfig(), Array.from(bytes));
  } catch { await audit(c, a, "failure"); return c.json({ error: "Invalid OPAQUE request" }, 400); }
  const sealed = await sealString(c.env, JSON.stringify(Array.from(bytes)), `opaque_record:${a.userId}`);
  // Snapshot before deleting sessions; their foreign keys may remove token evidence.
  const snapshot = await appSessionSnapshot(c.env, a.userId);
  const now = new Date().toISOString(); const claim = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  await insertAuditEvent(c.env, { id: eventId, actor_user_id: a.userId, target_user_id: a.userId,
    event_type: eventType, outcome: "started", request_path: c.req.path });
  const condition = "EXISTS (SELECT 1 FROM opaque_password_confirmations WHERE user_id = ? AND session_digest = ? AND claim = ?)";
  const result = await c.env.DB.batch([
    c.env.DB.prepare(`UPDATE opaque_password_confirmations SET claim = ? WHERE user_id = ? AND session_digest = ? AND claim IS NULL
      AND expires_at > ? AND EXISTS (SELECT 1 FROM opaque_credential_records r WHERE r.user_id = ? AND r.record = record_snapshot)`)
      .bind(claim, a.userId, a.digest, now, a.userId),
    c.env.DB.prepare(`UPDATE opaque_credential_records SET record = ?, updated_at = ? WHERE user_id = ? AND ${condition}`)
      .bind(sealed, now, a.userId, a.userId, a.digest, claim),
    c.env.DB.prepare(`UPDATE "oauthAccessToken" SET revoked = ? WHERE userId = ? AND revoked IS NULL AND ${condition}`)
      .bind(Date.now(), a.userId, a.userId, a.digest, claim),
    c.env.DB.prepare(`UPDATE "oauthRefreshToken" SET revoked = ?, rotationReplayResponse = NULL, rotationReplayExpiresAt = NULL WHERE userId = ? AND revoked IS NULL AND ${condition}`)
      .bind(Date.now(), a.userId, a.userId, a.digest, claim),
    c.env.DB.prepare(`DELETE FROM "session" WHERE "userId" = ? AND token != ? AND ${condition}`)
      .bind(a.userId, a.token, a.userId, a.digest, claim),
    c.env.DB.prepare("DELETE FROM opaque_password_confirmations WHERE user_id = ? AND session_digest = ? AND claim = ?")
      .bind(a.userId, a.digest, claim),
  ]);
  if (result[0]?.meta.changes !== 1 || result[1]?.meta.changes !== 1) {
    await updateAuditEvent(c.env, eventId, { actor_user_id: a.userId, target_user_id: a.userId, outcome: "failure" });
    return c.json({ error: "Password confirmation required" }, 403);
  }
  await recordPasswordChange(c.env, a.userId).catch(() => undefined);
  await logoutUserFromApps(c.env, a.userId, { reason: "password_change", snapshot });
  await updateAuditEvent(c.env, eventId, { actor_user_id: a.userId, target_user_id: a.userId, outcome: "success" });
  return c.json({ changed: true });
});
