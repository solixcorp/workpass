/**
 * Duo secondary-authentication routes (Duo Free edition includes the Auth
 * API): the acting user verifies with Duo Push, SMS passcodes, phone callback
 * or a hardware-token passcode through the /auth/v2/auth call.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { createAuth } from "../auth/config";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import { duoAuthCall, duoConfig } from "./duo";
import { sealString } from "../crypto/sealed";
import { generateHotpSecret, hotpEnrollVerify, hotpVerify, userHasHotpToken } from "./hotp";
import { mayEnrollFactor, recordSessionMfaProof } from "./second-factor";
import { mfaPolicy } from "./policy";
import { sendOtpWithFallback } from "./otp-senders";


export const mfaRoutes = new Hono<{ Bindings: Env }>();

mfaRoutes.post("/mfa/duo/verify", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: "The Duo verification cannot be processed" }, 403);
  }
  if (!duoConfig(context.env)) return context.json({ error: "Duo secondary authentication is not configured" }, 503);
  if (!mfaPolicy(context.env).allow.duo) return context.json({ error: "Duo secondary authentication is not allowed" }, 403);
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "The Duo verification cannot be processed" }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "The Duo verification cannot be processed" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  // This deployment uses Duo for PUSH NOTIFICATIONS ONLY. SMS passcodes and
  // hardware-token passcodes are managed by the platform's own factors
  // (phone-number OTP and HOTP tokens), not through Duo.
  return auditStandaloneOperation(context.env, "mfa.duo.verify", "/api/mfa/duo/verify", async () => {
    const result = await duoAuthCall(context.env, {
      user: session.user.email,
      factor: "push",
    });
    if (!result) {
      return { response: Response.json({ error: "Duo secondary authentication is not configured" }, { status: 503 }), actorUserId: session.user.id };
    }
    if (result.result === "allow") {
      // A push approval in this session is a session-bound second factor.
      const token = proofSessionToken(session);
      const verified = token !== null && await recordSessionMfaProof(context.env, token, session.user.id, "duo");
      if (!verified) {
        return { response: Response.json({ error: "The verification could not be recorded" }, { status: 503 }), actorUserId: session.user.id };
      }
    }
    return {
      response: Response.json({ result: result.result, status: result.status, statusMessage: result.statusMessage }),
      actorUserId: session.user.id,
    };
  }, { method: "duo" });
});

// --- Hardware OTP (HOTP) tokens managed by this platform ---------------------

mfaRoutes.post("/mfa/hotp/enroll", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: "The hardware token enrollment cannot be processed" }, 403);
  }
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "The hardware token enrollment cannot be processed" }, 401);
  if (!mfaPolicy(context.env).allow.hotp || !await mayEnrollFactor(context.env, session)) {
    return context.json({ error: "Additional verification is required or this method is unavailable" }, 403);
  }
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "The hardware token enrollment cannot be processed" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const label = typeof value.label === "string" && value.label.length > 0 && value.label.length <= 64 ? value.label : "";
  if (label.length === 0) return context.json({ error: "The hardware token enrollment cannot be processed" }, 400);
  const secret = await generateHotpSecret();
  const sealedSecret = await sealString(context.env, secret, `mfa_hotp_token:${session.user.id}`);
  const id = crypto.randomUUID();
  // Verify-gated enrollment: the token stays pending until its code verifies.
  await context.env.DB.prepare(
    "INSERT INTO mfa_hotp_tokens (id, user_id, label, secret_base32, counter, verified, created_at) VALUES (?, ?, ?, ?, 0, 0, ?)",
  ).bind(id, session.user.id, label, sealedSecret, new Date().toISOString()).run();
  return auditStandaloneOperation(context.env, "mfa.hotp.enroll", "/api/mfa/hotp/enroll", async () => ({
    response: Response.json({ tokenId: id, label, secretBase32: secret }, { status: 201 }),
    actorUserId: session.user.id,
  }), { method: "hotp", tokenLabel: label.trim().slice(0, 64) });
});

mfaRoutes.post("/mfa/hotp/verify", async (context) => {
  const baseOrigin = new URL(context.env.AUTH_BASE_URL).origin;
  if (context.req.header("origin") !== baseOrigin) {
    return context.json({ error: "The verification cannot be processed" }, 403);
  }
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "The verification cannot be processed" }, 401);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "The verification cannot be processed" }, 400); }
  const value = (body ?? {}) as Record<string, unknown>;
  const code = typeof value.code === "string" ? value.code : "";
  // The enrollment confirm step names its token; the sign-in proof path does
  // not (any verified token's code may satisfy it).
  const tokenId = typeof value.tokenId === "string" && value.tokenId.length > 0 ? value.tokenId.slice(0, 64) : null;
  if (!mfaPolicy(context.env).allow.hotp) return context.json({ error: "Hardware tokens are not allowed" }, 403);
  if (tokenId) {
    const row = await context.env.DB.prepare('SELECT verified FROM mfa_hotp_tokens WHERE id = ? AND user_id = ?')
      .bind(tokenId, session.user.id).first<{ verified: number }>();
    if (row && !row.verified && !await mayEnrollFactor(context.env, session)) {
      return context.json({ error: "Additional verification is required" }, 403);
    }
  }
  return auditStandaloneOperation(context.env, "mfa.hotp.verify", "/api/mfa/hotp/verify", async () => {
    const enrolled = tokenId
      ? await hotpEnrollVerify(context.env, session.user.id, tokenId, code)
      : null;
    if (tokenId && enrolled && !enrolled.verified && enrolled.notFound) {
      return { response: Response.json({ error: "That token is not enrolled" }, { status: 404 }), actorUserId: session.user.id };
    }
    const result = tokenId
      ? { verified: enrolled!.verified, tokenId }
      // Re-verifying an already-verified token still counts: the code proved
      // possession again.
      : await hotpVerify(context.env, session.user.id, code);
    if (result.verified) {
      const token = proofSessionToken(session);
      const recorded = token !== null && await recordSessionMfaProof(context.env, token, session.user.id, "hotp");
      if (!recorded) {
        // The code itself was correct, but the proof must be durable or MFA
        // policies cannot honor it later; do not report a passing verification.
        return { response: Response.json({ error: "The verification could not be recorded" }, { status: 503 }), actorUserId: session.user.id };
      }
    }
    return {
      response: Response.json({ verified: result.verified }, { status: result.verified ? 200 : 400 }),
      actorUserId: session.user.id,
    };
  }, { method: "hotp" });
});

async function enrollmentDigest(secret: string, userId: string, code: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const bytes = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`mfa-otp-enrollment:${userId}:${code}`));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

mfaRoutes.post("/mfa/otp/start", async (context) => {
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) return context.json({ error: "Invalid origin" }, 403);
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  if (!mfaPolicy(context.env).allow.otp) return context.json({ error: "One-time codes are not allowed" }, 403);
  if (!await mayEnrollFactor(context.env, session)) return context.json({ error: "Additional verification is required" }, 403);
  const user = await context.env.DB.prepare('SELECT email, twoFactorEnabled FROM "user" WHERE id = ?').bind(session.user.id)
    .first<{ email: string; twoFactorEnabled: number | boolean }>();
  if (!user?.email) return context.json({ error: "The enrollment cannot be processed" }, 400);
  if (user.twoFactorEnabled) return context.json({ error: "Two-factor authentication is already enabled" }, 409);
  return auditStandaloneOperation(context.env, "mfa.otp.enroll_start", "/api/mfa/otp/start", async () => {
    // Rejection sampling avoids modulo bias.
    const random = new Uint32Array(1);
    do { crypto.getRandomValues(random); } while (random[0]! >= 4294000000);
    const otp = String(random[0]! % 1000000).padStart(6, "0");
    const digest = await enrollmentDigest(context.env.AUTH_SECRET, session.user.id, otp);
    const now = Date.now();
    await context.env.DB.prepare("INSERT OR REPLACE INTO mfa_enroll_verifications (user_id, code_digest, attempts, created_at, expires_at) VALUES (?, ?, 0, ?, ?)")
      .bind(session.user.id, digest, now, now + 600000).run();
    try {
      await sendOtpWithFallback(context.env, { userId: session.user.id, email: user.email, otp });
    } catch {
      await context.env.DB.prepare("DELETE FROM mfa_enroll_verifications WHERE user_id = ? AND code_digest = ?").bind(session.user.id, digest).run();
      return { response: context.json({ error: "The verification code could not be sent" }, 503), actorUserId: session.user.id };
    }
    const method = await (await import("./otp-channel")).otpChannel(context.env, session.user.id, otp) ?? "otp";
    return { response: context.json({ sent: true, expires_in: 600 }), actorUserId: session.user.id, eventContext: { method } };
  }, { method: "otp" });
});

mfaRoutes.post("/mfa/otp/confirm", async (context) => {
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) return context.json({ error: "Invalid origin" }, 403);
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  if (!mfaPolicy(context.env).allow.otp) return context.json({ error: "One-time codes are not allowed" }, 403);
  if (!await mayEnrollFactor(context.env, session)) return context.json({ error: "Additional verification is required" }, 403);
  let body: { code?: unknown; password?: unknown };
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid verification request" }, 400); }
  if (!body || typeof body.code !== "string" || (body.password !== undefined && typeof body.password !== "string")) return context.json({ error: "Invalid verification request" }, 400);
  const row = await context.env.DB.prepare("SELECT code_digest, attempts, expires_at FROM mfa_enroll_verifications WHERE user_id = ?")
    .bind(session.user.id).first<{ code_digest: string; attempts: number; expires_at: number }>();
  if (!row) return context.json({ error: "Start enrollment first" }, 400);
  const remove = () => context.env.DB.prepare("DELETE FROM mfa_enroll_verifications WHERE user_id = ? AND code_digest = ?").bind(session.user.id, row.code_digest).run();
  if (row.expires_at <= Date.now()) { await remove(); return context.json({ error: "Verification code expired" }, 400); }
  if (row.attempts >= 5) { await remove(); return context.json({ error: "Too many attempts" }, 429); }
  const digest = await enrollmentDigest(context.env.AUTH_SECRET, session.user.id, body.code);
  if (digest !== row.code_digest) {
    await context.env.DB.prepare("UPDATE mfa_enroll_verifications SET attempts = attempts + 1 WHERE user_id = ? AND code_digest = ?").bind(session.user.id, row.code_digest).run();
    return context.json({ error: "Invalid verification code" }, 400);
  }
  const method = await (await import("./otp-channel")).otpChannel(context.env, session.user.id, body.code) ?? "otp";
  return auditStandaloneOperation(context.env, "mfa.otp.enroll_verified", "/api/mfa/otp/confirm", async () => {
    let response: Response;
    try {
      response = await createAuth(context.env).api.enableTwoFactor({ body: { method: "otp", ...(body.password ? { password: body.password as string } : {}) }, headers: context.req.raw.headers, asResponse: true });
    } catch {
      return { response: context.json({ error: "The enrollment could not be completed" }, 400), actorUserId: session.user.id };
    }
    if (!response.ok) return { response: context.json({ error: "The enrollment could not be completed" }, 400), actorUserId: session.user.id };
    await remove();
    return { response, actorUserId: session.user.id };
  }, { method });
});

interface MfaProofSession {
  user: { id: string };
  session?: { token?: unknown } | null;
}

/** The acting session token for a proof record (fail closed). */
function proofSessionToken(session: MfaProofSession): string | null {
  const token = session.session?.token;
  return typeof token === "string" && token.length > 0 && token.length <= 512 ? token : null;
}

// The admin-facing second-factor status endpoint (display only); the SSO
// routes gate on sessionSatisfiesRequireMfa (src/mfa/second-factor.ts).
mfaRoutes.get("/mfa/second-factor", async (context) => {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const twoFactorEnabled = session.user.twoFactorEnabled === true;
  const hotp = await userHasHotpToken(context.env, session.user.id);
  return context.json({ secondFactor: twoFactorEnabled || hotp, via: twoFactorEnabled ? "better-auth" : hotp ? "hardware-otp" : null });
});
