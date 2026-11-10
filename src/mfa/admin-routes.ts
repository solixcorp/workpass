/**
 * Administrator controls over a user's second factors.
 *
 *   GET    /api/admin/users/:id/mfa                  -> what the user has enrolled
 *   POST   /api/admin/users/:id/mfa/hotp             -> attach a hardware token seed
 *   DELETE /api/admin/users/:id/mfa/hotp/:tokenId    -> remove one token
 *   POST   /api/admin/users/:id/mfa/reset            -> clear every second factor
 *
 * Secrets of authenticator apps are never readable or settable here: they only
 * exist on the user's own device. A hardware token's seed comes from its vendor,
 * so an administrator may attach it on the user's behalf.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { sealString } from "../crypto/sealed";
import { mfaPolicy, userMustUseMfa } from "./policy";
import { usableSecondFactors } from "../security/step-up";

export const mfaAdminRoutes = new Hono<{ Bindings: Env }>();

mfaAdminRoutes.use("/users/:id/mfa*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

async function loadUser(env: Env, id: string) {
  return await env.DB.prepare('SELECT id, email, role, "twoFactorEnabled" AS twoFactorEnabled FROM "user" WHERE id = ? LIMIT 1')
    .bind(id).first<{ id: string; email: string; role: string | null; twoFactorEnabled: number | boolean | null }>();
}

mfaAdminRoutes.get("/users/:id/mfa", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const user = await loadUser(context.env, context.req.param("id"));
  if (!user) return context.json({ error: "사용자를 찾을 수 없습니다." }, 404);
  const secret = await context.env.DB.prepare('SELECT verified FROM "twoFactor" WHERE userId = ? LIMIT 1')
    .bind(user.id).first<{ verified: number | boolean | null }>().catch(() => null);
  const tokens = await context.env.DB.prepare(
    "SELECT id, label, created_at AS createdAt FROM mfa_hotp_tokens WHERE user_id = ? ORDER BY created_at ASC LIMIT 20",
  ).bind(user.id).all<{ id: string; label: string; createdAt: string }>();
  const factors = await usableSecondFactors(context.env, user.id);
  return context.json({
    required: userMustUseMfa(context.env, user),
    enrolled: factors.length > 0,
    twoFactorEnabled: user.twoFactorEnabled === 1 || user.twoFactorEnabled === true,
    authenticatorApp: secret !== null && secret.verified !== 0 && secret.verified !== false,
    hotpTokens: tokens.results,
    allowed: mfaPolicy(context.env).allow,
  });
});

mfaAdminRoutes.post("/users/:id/mfa/hotp", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const userId = context.req.param("id");
  let body: { label?: unknown; secretBase32?: unknown } | null = null;
  try { body = await context.req.json(); } catch { /* handled below */ }
  const label = typeof body?.label === "string" ? body.label.trim() : "";
  const seed = typeof body?.secretBase32 === "string" ? body.secretBase32.replace(/[\s-]/g, "").toUpperCase() : "";
  if (label.length === 0 || label.length > 64) return context.json({ error: "토큰 이름을 1~64자로 입력하세요." }, 400);
  if (!/^[A-Z2-7]{16,128}={0,6}$/.test(seed)) return context.json({ error: "토큰 키는 Base32 문자(A-Z, 2-7) 16자 이상이어야 합니다." }, 400);
  if (!mfaPolicy(context.env).allow.hotp) return context.json({ error: "보안 토큰이 허용되지 않은 상태입니다." }, 409);
  return auditStandaloneOperation(context.env, "mfa.hotp.admin_attach", `/api/admin/users/${userId}/mfa/hotp`, async () => {
    const user = await loadUser(context.env, userId);
    if (!user) return { response: context.json({ error: "사용자를 찾을 수 없습니다." }, 404), actorUserId: actor.userId };
    const id = crypto.randomUUID();
    const sealed = await sealString(context.env, seed, `mfa_hotp_token:${user.id}`);
    await context.env.DB.prepare(
      "INSERT INTO mfa_hotp_tokens (id, user_id, label, secret_base32, counter, created_at) VALUES (?, ?, ?, ?, 0, ?)",
    ).bind(id, user.id, label, sealed, new Date().toISOString()).run();
    return { response: context.json({ token: { id, label } }, 201), actorUserId: actor.userId, targetUserId: user.id };
  });
});

mfaAdminRoutes.delete("/users/:id/mfa/hotp/:tokenId", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const userId = context.req.param("id");
  return auditStandaloneOperation(context.env, "mfa.hotp.admin_remove", `/api/admin/users/${userId}/mfa/hotp`, async () => {
    const result = await context.env.DB.prepare("DELETE FROM mfa_hotp_tokens WHERE id = ? AND user_id = ?")
      .bind(context.req.param("tokenId"), userId).run();
    return {
      response: result.meta.changes === 1 ? context.json({ removed: true }) : context.json({ error: "토큰을 찾을 수 없습니다." }, 404),
      actorUserId: actor.userId,
      targetUserId: userId,
    };
  });
});

mfaAdminRoutes.post("/users/:id/mfa/reset", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const userId = context.req.param("id");
  return auditStandaloneOperation(context.env, "mfa.admin_reset", `/api/admin/users/${userId}/mfa/reset`, async () => {
    const user = await loadUser(context.env, userId);
    if (!user) return { response: context.json({ error: "사용자를 찾을 수 없습니다." }, 404), actorUserId: actor.userId };
    await context.env.DB.batch([
      context.env.DB.prepare('DELETE FROM "twoFactor" WHERE userId = ?').bind(user.id),
      context.env.DB.prepare('UPDATE "user" SET "twoFactorEnabled" = 0 WHERE id = ?').bind(user.id),
      context.env.DB.prepare("DELETE FROM mfa_hotp_tokens WHERE user_id = ?").bind(user.id),
      context.env.DB.prepare("DELETE FROM session_mfa_proofs WHERE user_id = ?").bind(user.id),
      context.env.DB.prepare("DELETE FROM session_step_up_requirements WHERE user_id = ?").bind(user.id),
    ]);
    return { response: context.json({ reset: true }), actorUserId: actor.userId, targetUserId: user.id };
  });
});
