/**
 * Step-up challenge status for the acting session: lets the sign-in surface
 * and applications learn that a risky decision requires a second factor,
 * including which factors the account can complete and until when the
 * challenge window stays open.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { getSessionMfaProof } from "../mfa/second-factor";
import { workpassMfaRequired } from "../mfa/policy";
import {
  openStepUpChallenge,
  getStepUpChallenge,
  usableSecondFactors,
  type StepUpChallenge,
} from "./step-up";
import { sessionTokenFromRequest } from "./session-geo-binding";
import { stepUpUi } from "./step-up-ui";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON, AuthenticatorTransportFuture } from "@simplewebauthn/server";
import { auditStandaloneOperation } from "../audit/store";
import { recordSessionMfaProof } from "../mfa/second-factor";

export const stepUpRoutes = new Hono<{ Bindings: Env }>();

const REQUEST_PATH = "/api/security/step-up/challenge";

stepUpRoutes.use("/step-up/passkey/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

type PasskeyRow = { id: string; credentialID: string; publicKey: string; counter: number; transports: string | null };
const transports = (value: string | null): AuthenticatorTransportFuture[] | undefined =>
  value ? value.split(",") as AuthenticatorTransportFuture[] : undefined;

/** Atomic per-user, per-route fixed-minute budget, shared across isolates. */
async function passkeyBudget(env: Env, userId: string, route: "options" | "verify"): Promise<{ allowed: boolean; retryAfter: number } | null> {
  const now = Date.now();
  const window = Math.floor(now / 60_000);
  try {
    const row = await env.DB.prepare(
      `INSERT INTO fingerprint_lookup_limits (budget_key, window_start, request_count)
       VALUES (?, ?, 1)
       ON CONFLICT(budget_key) DO UPDATE SET
         request_count = CASE WHEN fingerprint_lookup_limits.window_start = excluded.window_start
           THEN fingerprint_lookup_limits.request_count + 1 ELSE 1 END,
         window_start = excluded.window_start
       RETURNING request_count`,
    ).bind(`passkey_step_up:${route}:${userId}`, window).first<{ request_count: number }>();
    if (!row || !Number.isSafeInteger(row.request_count)) return null;
    return { allowed: row.request_count <= 10, retryAfter: Math.max(1, Math.ceil(((window + 1) * 60_000 - now) / 1000)) };
  } catch {
    return null;
  }
}

stepUpRoutes.post("/step-up/passkey/options", async (context) => {
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) return context.json({ error: "Invalid origin" }, 403);
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const token = session.session.token;
  if (!token || token.length > 512) return context.json({ error: "Unauthorized" }, 401);
  const budget = await passkeyBudget(context.env, session.user.id, "options");
  if (!budget) return context.json({ error: "요청을 처리할 수 없습니다." }, 503);
  if (!budget.allowed) return context.json({ error: "잠시 뒤에 다시 시도하세요." }, 429, { "Retry-After": String(budget.retryAfter) });
  const keys = await context.env.DB.prepare('SELECT "credentialID", transports FROM "passkey" WHERE "userId" = ?')
    .bind(session.user.id).all<Pick<PasskeyRow, "credentialID" | "transports">>();
  if (!keys.results.length) return context.json({ error: "등록된 패스키가 없습니다." }, 409);
  const options = await generateAuthenticationOptions({
    rpID: new URL(context.env.AUTH_BASE_URL).hostname,
    userVerification: "required",
    allowCredentials: keys.results.map((key) => ({ id: key.credentialID, transports: transports(key.transports) })),
  });
  await context.env.DB.prepare(`INSERT INTO step_up_passkey_challenges (session_token, user_id, challenge, expires_at)
    VALUES (?, ?, ?, ?) ON CONFLICT(session_token) DO UPDATE SET user_id = excluded.user_id,
    challenge = excluded.challenge, expires_at = excluded.expires_at`)
    .bind(token, session.user.id, options.challenge, new Date(Date.now() + 300_000).toISOString()).run();
  return context.json(options);
});

stepUpRoutes.post("/step-up/passkey/verify", async (context) => {
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) return context.json({ error: "Invalid origin" }, 403);
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const token = session.session.token;
  if (!token || token.length > 512) return context.json({ error: "Unauthorized" }, 401);
  const budget = await passkeyBudget(context.env, session.user.id, "verify");
  if (!budget) return context.json({ error: "요청을 처리할 수 없습니다." }, 503);
  if (!budget.allowed) return context.json({ error: "잠시 뒤에 다시 시도하세요." }, 429, { "Retry-After": String(budget.retryAfter) });
  return auditStandaloneOperation(context.env, "mfa.passkey.step_up", "/api/security/step-up/passkey/verify", async () => {
    const failure = () => ({ response: Response.json({ error: "패스키를 확인하지 못했습니다." }, { status: 401 }), actorUserId: session.user.id });
    try {
      // Atomic consume prevents simultaneous requests from reusing a challenge.
      const challenge = await context.env.DB.prepare('DELETE FROM step_up_passkey_challenges WHERE session_token = ? AND user_id = ? RETURNING challenge, expires_at')
        .bind(token, session.user.id).first<{ challenge: string; expires_at: string }>();
      if (!challenge || !(Date.parse(challenge.expires_at) > Date.now())) return failure();
      const response = await context.req.json() as AuthenticationResponseJSON;
      if (!response || typeof response.id !== "string") return failure();
      const key = await context.env.DB.prepare('SELECT id, "credentialID", "publicKey", counter, transports FROM "passkey" WHERE "credentialID" = ? AND "userId" = ? LIMIT 1')
        .bind(response.id, session.user.id).first<PasskeyRow>();
      if (!key) return failure();
      const origin = new URL(context.env.AUTH_BASE_URL);
      const verified = await verifyAuthenticationResponse({
        response, expectedChallenge: challenge.challenge, expectedOrigin: origin.origin, expectedRPID: origin.hostname,
        credential: { id: key.credentialID, publicKey: Uint8Array.from(atob(key.publicKey), (c) => c.charCodeAt(0)), counter: key.counter, transports: transports(key.transports) },
        requireUserVerification: true,
      });
      if (!verified.verified) return failure();
      // Compare-and-swap also rejects concurrent use of an old counter.
      const updated = await context.env.DB.prepare('UPDATE "passkey" SET counter = ? WHERE id = ? AND "userId" = ? AND counter = ?')
        .bind(verified.authenticationInfo.newCounter, key.id, session.user.id, key.counter).run();
      if (updated.meta.changes !== 1 || !await recordSessionMfaProof(context.env, token, session.user.id, "passkey")) return failure();
      return { response: Response.json({ verified: true }), actorUserId: session.user.id };
    } catch {
      return failure();
    }
  });
});

stepUpRoutes.get("/step-up/challenge", async (context) => {
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const subject = context.req.query("subject");
  if (subject) {
    const policy = await (await import("../access/policies")).loadAppAccessPolicy(context.env, subject);
    if (!policy?.requireMfa || !policy.mfaMethods?.length) return context.json({ required: false, state: "none" });
    const satisfied = await (await import("../mfa/second-factor")).sessionSatisfiesRequireMfa(context.env, session, policy.mfaMethods);
    if (satisfied) return context.json({ required: false, state: "satisfied" });
    return (await import("./step-up")).appMfaChallenge(context.env, session.user.id, policy.mfaMethods);
  }
  const token = sessionTokenFromRequest(context.req.raw) ??
    (typeof (session.session as { token?: unknown } | undefined)?.token === "string"
      ? ((session.session as { token: string }).token)
      : null);
  let challenge: StepUpChallenge = await getStepUpChallenge(context.env, token ?? "");
  // A required second factor opens its own challenge the first time the
  // session is looked at, whichever sign-in path created it (OPAQUE, passkey).
  if ((challenge.state === "none" || challenge.state === "expired") && token) {
    const user = session.user as { id: string; role?: unknown };
    const proven = await getSessionMfaProof(context.env, token).catch(() => null);
    if (!proven && (await workpassMfaRequired(context.env, user))) {
      const available = await usableSecondFactors(context.env, user.id);
      if (available.length > 0 && await openStepUpChallenge({
        env: context.env, sessionToken: token, userId: user.id, reasons: ["mfa_required"], requestPath: REQUEST_PATH,
      }).catch(() => false)) {
        challenge = await getStepUpChallenge(context.env, token);
      }
    }
  }
  if (challenge.state === "none") {
    return context.json({ required: false, state: "none" });
  }
  if (challenge.state === "satisfied") {
    return context.json({
      required: false,
      state: "satisfied",
      satisfiedAt: challenge.satisfiedAt,
      satisfiedMethod: challenge.satisfiedMethod,
    });
  }
  const methods = await usableSecondFactors(context.env, session.user.id);
  return context.json({
    required: true,
    state: challenge.state,
    reasons: challenge.reasons,
    expiresAt: challenge.expiresAt,
    methods,
    ui: stepUpUi(methods, challenge.reasons),
  });
});
