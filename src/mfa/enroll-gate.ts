/**
 * Reverification before a second factor is added.
 *
 * A stolen session must not be able to attach its own authenticator. Adding
 * any factor therefore needs, from the acting session and within
 * ENROLL_GATE_TTL_MS: (1) a fresh proof of the account password, run as a
 * session-bound OPAQUE exchange that issues no new session, and (2) a second
 * verification. The second verification is one of the account's existing
 * factors (recorded as a session MFA proof elsewhere) or, when the account has
 * none, a one-time code sent to the account's own address.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { base64Decode, base64Encode, opaqueBadRequest, opaqueConfig, opaqueServer } from "../auth/opaque";
import { clientIp, loadCredentialRecord, rateBucket, wireToBase64 } from "../auth/opaque-routes";
import { auditStandaloneOperation } from "../audit/store";
import { sendOtpWithFallback } from "./otp-senders";
import { enrollGateState, ENROLL_GATE_TTL_MS } from "./second-factor";

export const mfaEnrollGateRoutes = new Hono<{ Bindings: Env }>();

const TRANSCRIPT_TTL_MS = 2 * 60 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;

async function actingSession(context: { env: Env; req: { raw: Request; header(name: string): string | undefined } }) {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  const token = session?.session?.token;
  if (!session || typeof token !== "string" || token.length === 0 || token.length > 512) return null;
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) return null;
  return { session, token, userId: session.user.id };
}

async function codeDigest(env: Env, userId: string, code: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const bytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`mfa-enroll-gate:${userId}:${code}`));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

mfaEnrollGateRoutes.use("/mfa/gate/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

mfaEnrollGateRoutes.post("/mfa/gate/password/start", async (context) => {
  const acting = await actingSession(context);
  if (!acting) return context.json({ error: "Unauthorized" }, 401);
  let body: { ke1?: unknown };
  try { body = await context.req.json(); } catch { return opaqueBadRequest(context, "The verification could not be processed"); }
  let ke1Wire: string;
  try { ke1Wire = wireToBase64(body?.ke1); } catch { return opaqueBadRequest(context, "The verification could not be processed"); }
  if (!(await rateBucket(context.env, `gate:${acting.userId}`))) return context.json({ error: "Too many attempts; retry later" }, 429);
  try {
    const stored = await loadCredentialRecord(context.env, acting.userId);
    if (!stored) return context.json({ error: "이 계정에는 확인할 비밀번호가 없습니다. 관리자에게 문의하세요." }, 409);
    const config = opaqueConfig();
    const { KE1, RegistrationRecord } = await import("@cloudflare/opaque-ts");
    const { server } = await opaqueServer(context.env);
    const record = RegistrationRecord.deserialize(config, Array.from(stored.record));
    const init = await server.authInit(KE1.deserialize(config, Array.from(base64Decode(ke1Wire))), record, stored.identity, stored.identity);
    if (init instanceof Error) return opaqueBadRequest(context, "The verification could not be processed");
    const id = crypto.randomUUID();
    const now = Date.now();
    await context.env.DB.prepare("DELETE FROM mfa_gate_transcripts WHERE expires_at < ?").bind(now).run();
    await context.env.DB.prepare("INSERT INTO mfa_gate_transcripts (id, user_id, session_token, expected, expires_at) VALUES (?, ?, ?, ?, ?)")
      .bind(id, acting.userId, acting.token, JSON.stringify(Array.from(init.expected.serialize())), now + TRANSCRIPT_TTL_MS).run();
    return context.json({
      ke2: base64Encode(new Uint8Array(init.ke2.serialize())),
      credentialIdentifier: stored.identity,
      serverIdentity: new URL(context.env.AUTH_BASE_URL).origin,
      transcriptId: id,
    });
  } catch (error) {
    console.error("mfa gate password start failure", error instanceof Error ? error.message : String(error));
    return opaqueBadRequest(context, "The verification could not be processed", 503);
  }
});

mfaEnrollGateRoutes.post("/mfa/gate/password/finish", async (context) => {
  const acting = await actingSession(context);
  if (!acting) return context.json({ error: "Unauthorized" }, 401);
  let body: { ke3?: unknown; transcriptId?: unknown };
  try { body = await context.req.json(); } catch { return opaqueBadRequest(context, "The verification could not be processed"); }
  let ke3Bytes: Uint8Array;
  try { ke3Bytes = base64Decode(wireToBase64(body?.ke3)); } catch { return opaqueBadRequest(context, "The verification could not be processed"); }
  const transcriptId = typeof body.transcriptId === "string" && body.transcriptId.length <= 64 ? body.transcriptId : "";
  if (!transcriptId) return opaqueBadRequest(context, "The verification could not be processed", 401);
  if (!(await rateBucket(context.env, `gate:${acting.userId}`))) return context.json({ error: "Too many attempts; retry later" }, 429);
  return auditStandaloneOperation(context.env, "mfa.gate.password", "/api/mfa/gate/password/finish", async () => {
    // Single use, and bound to this session and user.
    const row = await context.env.DB.prepare(
      "DELETE FROM mfa_gate_transcripts WHERE id = ? AND user_id = ? AND session_token = ? AND expires_at > ? RETURNING expected",
    ).bind(transcriptId, acting.userId, acting.token, Date.now()).first<{ expected: string }>().catch(() => null);
    if (!row) return { response: opaqueBadRequest(context, "비밀번호가 올바르지 않습니다.", 401), actorUserId: acting.userId };
    const config = opaqueConfig();
    const { KE3, ExpectedAuthResult } = await import("@cloudflare/opaque-ts");
    const { server } = await opaqueServer(context.env);
    let proof: ReturnType<typeof server.authFinish>;
    try {
      proof = server.authFinish(KE3.deserialize(config, Array.from(ke3Bytes)), ExpectedAuthResult.deserialize(config, JSON.parse(row.expected) as number[]));
    } catch {
      proof = new Error("Malformed OPAQUE message");
    }
    if (proof instanceof Error) {
      return { response: opaqueBadRequest(context, "비밀번호가 올바르지 않습니다.", 401), actorUserId: acting.userId, eventContext: { outcome: "invalid" } };
    }
    await context.env.DB.prepare(
      `INSERT INTO mfa_enroll_gates (session_token, user_id, password_at) VALUES (?, ?, ?)
       ON CONFLICT (session_token) DO UPDATE SET
         password_at = excluded.password_at,
         second_at = CASE WHEN mfa_enroll_gates.user_id = excluded.user_id THEN mfa_enroll_gates.second_at ELSE NULL END,
         user_id = excluded.user_id`,
    ).bind(acting.token, acting.userId, Date.now()).run();
    return { response: context.json({ verified: true, validForSeconds: ENROLL_GATE_TTL_MS / 1000 }), actorUserId: acting.userId };
  }, { method: "password" });
});

/** One-time code to the account's own address: the minimum second check when no factor exists yet. */
mfaEnrollGateRoutes.post("/mfa/gate/code/start", async (context) => {
  const acting = await actingSession(context);
  if (!acting) return context.json({ error: "Unauthorized" }, 401);
  if (!(await rateBucket(context.env, `gate:${acting.userId}`))) return context.json({ error: "Too many attempts; retry later" }, 429);
  let state;
  try { state = await enrollGateState(context.env, acting.session); } catch { return context.json({ error: "확인 상태를 불러오지 못했습니다." }, 503); }
  if (state.secondMode !== "email") return context.json({ error: "이미 등록한 인증 수단으로 확인하세요." }, 409);
  const user = await context.env.DB.prepare('SELECT email FROM "user" WHERE id = ?').bind(acting.userId).first<{ email: string }>();
  if (!user?.email) return context.json({ error: "이메일이 없어 코드를 보낼 수 없습니다." }, 409);
  return auditStandaloneOperation(context.env, "mfa.gate.code_start", "/api/mfa/gate/code/start", async () => {
    const random = new Uint32Array(1);
    do { crypto.getRandomValues(random); } while (random[0]! >= 4294000000);
    const otp = String(random[0]! % 1000000).padStart(6, "0");
    const digest = await codeDigest(context.env, acting.userId, otp);
    await context.env.DB.prepare(
      `INSERT INTO mfa_enroll_gates (session_token, user_id, code_digest, code_attempts, code_expires_at) VALUES (?, ?, ?, 0, ?)
       ON CONFLICT (session_token) DO UPDATE SET code_digest = excluded.code_digest, code_attempts = 0, code_expires_at = excluded.code_expires_at,
         password_at = CASE WHEN mfa_enroll_gates.user_id = excluded.user_id THEN mfa_enroll_gates.password_at ELSE NULL END,
         second_at = CASE WHEN mfa_enroll_gates.user_id = excluded.user_id THEN mfa_enroll_gates.second_at ELSE NULL END,
         user_id = excluded.user_id`,
    ).bind(acting.token, acting.userId, digest, Date.now() + CODE_TTL_MS).run();
    try {
      await sendOtpWithFallback(context.env, { userId: acting.userId, email: user.email, otp });
    } catch {
      await context.env.DB.prepare("UPDATE mfa_enroll_gates SET code_digest = NULL, code_expires_at = NULL WHERE session_token = ?").bind(acting.token).run();
      return { response: context.json({ error: "확인 코드를 보내지 못했습니다." }, 503), actorUserId: acting.userId };
    }
    return { response: context.json({ sent: true, expiresIn: CODE_TTL_MS / 1000 }), actorUserId: acting.userId };
  }, { method: "otp" });
});

mfaEnrollGateRoutes.post("/mfa/gate/code/confirm", async (context) => {
  const acting = await actingSession(context);
  if (!acting) return context.json({ error: "Unauthorized" }, 401);
  let body: { code?: unknown };
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid verification request" }, 400); }
  const code = typeof body?.code === "string" ? body.code.trim() : "";
  if (!/^[0-9]{6}$/.test(code)) return context.json({ error: "6자리 코드를 입력하세요." }, 400);
  return auditStandaloneOperation(context.env, "mfa.gate.code_confirm", "/api/mfa/gate/code/confirm", async () => {
    const row = await context.env.DB.prepare(
      "SELECT user_id AS userId, code_digest AS digest, code_attempts AS attempts, code_expires_at AS expiresAt FROM mfa_enroll_gates WHERE session_token = ?",
    ).bind(acting.token).first<{ userId: string; digest: string | null; attempts: number; expiresAt: number | null }>();
    if (!row || row.userId !== acting.userId || !row.digest || !row.expiresAt) {
      return { response: context.json({ error: "먼저 코드를 받으세요." }, 400), actorUserId: acting.userId };
    }
    const clear = () => context.env.DB.prepare("UPDATE mfa_enroll_gates SET code_digest = NULL, code_expires_at = NULL, code_attempts = 0 WHERE session_token = ?").bind(acting.token).run();
    if (row.expiresAt <= Date.now()) { await clear(); return { response: context.json({ error: "코드가 만료되었습니다." }, 400), actorUserId: acting.userId }; }
    if (row.attempts >= MAX_CODE_ATTEMPTS) { await clear(); return { response: context.json({ error: "시도 횟수를 넘었습니다. 코드를 다시 받으세요." }, 429), actorUserId: acting.userId }; }
    if (await codeDigest(context.env, acting.userId, code) !== row.digest) {
      await context.env.DB.prepare("UPDATE mfa_enroll_gates SET code_attempts = code_attempts + 1 WHERE session_token = ?").bind(acting.token).run();
      return { response: context.json({ error: "코드가 올바르지 않습니다." }, 400), actorUserId: acting.userId };
    }
    await context.env.DB.prepare("UPDATE mfa_enroll_gates SET second_at = ?, code_digest = NULL, code_expires_at = NULL, code_attempts = 0 WHERE session_token = ?")
      .bind(Date.now(), acting.token).run();
    return { response: context.json({ verified: true }), actorUserId: acting.userId };
  }, { method: "otp" });
});

/** Gates outlive neither their window nor the session that earned them. */
export async function cleanupEnrollGates(env: Env, now = Date.now()): Promise<void> {
  const cutoff = now - 2 * ENROLL_GATE_TTL_MS;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM mfa_enroll_gates WHERE COALESCE(second_at, password_at, 0) < ? AND COALESCE(code_expires_at, 0) < ?").bind(cutoff, now),
    env.DB.prepare("DELETE FROM mfa_gate_transcripts WHERE expires_at < ?").bind(now),
  ]);
}
