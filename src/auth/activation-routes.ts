/**
 * Account activation endpoints (docs/design/account-activation.md).
 *
 * Public, token-authorized, rate limited:
 *   POST /api/activation/inspect          -> screen definition + the account's email
 *   POST /api/activation/register/start   -> OPAQUE registration response
 *   POST /api/activation/register/finish  -> stores the credential, consumes the link
 *
 * Administrator:
 *   POST /api/admin/users                          -> create a user and issue a link
 *   POST /api/admin/users/:id/activation-link      -> issue a new link for a user
 *
 * Activation never creates a session. An unknown, expired or used link gets
 * the same answer, so the endpoints reveal nothing about accounts.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { notifySecurityEvent } from "../users/security-notices";
import { opaqueConfig, opaqueIdentityFor, opaqueServer, base64Decode, base64Encode } from "./opaque";
import { clientIp, rateBucket, storeCredentialRecord, wireToBase64 } from "./opaque-routes";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation, insertAuditEvent } from "../audit/store";
import {
  activationUrl,
  activeAndBoundPasswordRules,
  consumeActivation,
  findOpenActivation,
  issueActivationLink,
  markActivationDelivered,
  type PasswordRules,
} from "../security/account-activation";
import { sendTransactionEmail, transactionEmailAvailable } from "../mail/send";
import { recordPasswordChange } from "../policies/password";

export const activationRoutes = new Hono<{ Bindings: Env }>();

const GENERIC_REJECTION = "링크가 올바르지 않거나 만료되었습니다. 관리자에게 새 링크를 요청하세요.";

const MESSAGES = {
  mismatch: "두 비밀번호가 같지 않습니다.",
  min_length: (rules: PasswordRules) => `비밀번호는 ${rules.minLength}자 이상이어야 합니다.`,
  min_upper: (rules: PasswordRules) => `대문자를 ${rules.minUpper}개 이상 포함하세요.`,
  min_lower: (rules: PasswordRules) => `소문자를 ${rules.minLower}개 이상 포함하세요.`,
  min_digit: (rules: PasswordRules) => `숫자를 ${rules.minDigit}개 이상 포함하세요.`,
  min_symbol: (rules: PasswordRules) => `기호를 ${rules.minSymbol}개 이상 포함하세요.`,
};

/** The screen for the activation page; the client renders it as-is. */
function activationUi(email: string, rules: PasswordRules) {
  const requirements = [
    `${rules.minLength}자 이상`,
    ...(rules.minUpper > 0 ? [`대문자 ${rules.minUpper}개 이상`] : []),
    ...(rules.minLower > 0 ? [`소문자 ${rules.minLower}개 이상`] : []),
    ...(rules.minDigit > 0 ? [`숫자 ${rules.minDigit}개 이상`] : []),
    ...(rules.minSymbol > 0 ? [`기호 ${rules.minSymbol}개 이상`] : []),
  ];
  return {
    title: "비밀번호 설정",
    description: `${email} 계정에서 사용할 비밀번호를 정하세요.`,
    requirements,
    rules,
    fields: [
      { name: "password", label: "새 비밀번호", autocomplete: "new-password" },
      { name: "confirm", label: "비밀번호 확인", autocomplete: "new-password" },
    ],
    submit: { label: "비밀번호 설정" },
    done: {
      title: "비밀번호를 설정했습니다",
      description: "이제 로그인할 수 있습니다.",
      action: "로그인",
    },
    messages: {
      mismatch: MESSAGES.mismatch,
      min_length: MESSAGES.min_length(rules),
      min_upper: MESSAGES.min_upper(rules),
      min_lower: MESSAGES.min_lower(rules),
      min_digit: MESSAGES.min_digit(rules),
      min_symbol: MESSAGES.min_symbol(rules),
      invalid_link: GENERIC_REJECTION,
      rate_limited: "시도가 너무 많습니다. 잠시 후 다시 시도하세요.",
      unavailable: "지금은 설정할 수 없습니다. 잠시 후 다시 시도하세요.",
    },
  };
}

async function readBody(context: Context<{ Bindings: Env }>): Promise<Record<string, unknown>> {
  try {
    const body = await context.req.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

async function limited(context: Context<{ Bindings: Env }>): Promise<Response | null> {
  if (await rateBucket(context.env, `activation:${clientIp(context)}`)) return null;
  return context.json({ error: "시도가 너무 많습니다. 잠시 후 다시 시도하세요." }, 429);
}

activationRoutes.use("/api/activation/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  context.header("Referrer-Policy", "no-referrer");
  await next();
});

activationRoutes.post("/api/activation/inspect", async (context) => {
  const blocked = await limited(context);
  if (blocked) return blocked;
  const body = await readBody(context);
  const link = await findOpenActivation(context.env, body.token);
  if (!link) return context.json({ error: GENERIC_REJECTION }, 404);
  const rules = await activeAndBoundPasswordRules(context.env);
  return context.json({ email: link.email, expiresAt: link.expiresAt, ui: activationUi(link.email, rules) });
});

activationRoutes.post("/api/activation/register/start", async (context) => {
  const blocked = await limited(context);
  if (blocked) return blocked;
  const body = await readBody(context);
  const link = await findOpenActivation(context.env, body.token);
  if (!link) return context.json({ error: GENERIC_REJECTION }, 404);
  let wire: string;
  try {
    wire = wireToBase64(body.registrationRequest);
  } catch {
    return context.json({ error: GENERIC_REJECTION }, 400);
  }
  const config = opaqueConfig();
  const { RegistrationRequest } = await import("@cloudflare/opaque-ts");
  const identity = opaqueIdentityFor(link.email);
  const { server } = await opaqueServer(context.env);
  const request = RegistrationRequest.deserialize(config, Array.from(base64Decode(wire)));
  const response = await server.registerInit(request, identity);
  if (response instanceof Error) return context.json({ error: GENERIC_REJECTION }, 400);
  return context.json({
    registrationResponse: base64Encode(new Uint8Array(response.serialize())),
    credentialIdentifier: identity,
    serverIdentity: new URL(context.env.AUTH_BASE_URL).origin,
  });
});

activationRoutes.post("/api/activation/register/finish", async (context) => {
  const blocked = await limited(context);
  if (blocked) return blocked;
  const body = await readBody(context);
  const link = await findOpenActivation(context.env, body.token);
  if (!link) return context.json({ error: GENERIC_REJECTION }, 404);
  let recordBytes: Uint8Array;
  try {
    recordBytes = base64Decode(wireToBase64(body.record));
    const { RegistrationRecord } = await import("@cloudflare/opaque-ts");
    RegistrationRecord.deserialize(opaqueConfig(), Array.from(recordBytes));
  } catch {
    return context.json({ error: GENERIC_REJECTION }, 400);
  }

  // Consume first: a second submit with the same link must fail.
  if (!(await consumeActivation(context.env, link))) {
    return context.json({ error: GENERIC_REJECTION }, 404);
  }
  await storeCredentialRecord(context.env, link.userId, opaqueIdentityFor(link.email), recordBytes);
  // OPAQUE keeps the password from the server: only the change time is recorded
  // (reuse history needs the plaintext and cannot apply to this path).
  await recordPasswordChange(context.env, link.userId).catch(() => undefined);
  await insertAuditEvent(context.env, {
    id: crypto.randomUUID(),
    actor_user_id: link.userId,
    target_user_id: link.userId,
    event_type: "identity.user.activation.completed",
    outcome: "success",
    request_path: "/api/activation/register/finish",
    client_ip: clientIp(context),
  }).catch(() => console.error("Activation audit event could not be recorded"));
  await notifySecurityEvent(context.env, "identity.user.password_change.success_or_failure", link.userId);
  return context.json({ activated: true });
});

// --- administrator -------------------------------------------------------

async function deliver(env: Env, email: string, name: string, token: string): Promise<boolean> {
  if (!transactionEmailAvailable(env)) return false;
  await sendTransactionEmail(env, {
    to: email,
    subject: "WorkPass 비밀번호를 설정하세요",
    text: [
      `${name}님, 안녕하세요.`,
      "",
      "아래 링크에서 WorkPass 비밀번호를 설정할 수 있습니다. 링크는 한 번만 사용할 수 있고 곧 만료됩니다.",
      "",
      activationUrl(env, token),
      "",
      "요청한 적이 없다면 이 메일을 무시하세요.",
    ].join("\n"),
  });
  await markActivationDelivered(env, token);
  return true;
}

async function issueAndDeliver(
  context: Context<{ Bindings: Env }>,
  actorUserId: string,
  user: { id: string; email: string; name: string },
  sendEmail: boolean,
) {
  const wantsEmail = sendEmail && transactionEmailAvailable(context.env);
  const link = await issueActivationLink({
    env: context.env,
    userId: user.id,
    actorUserId,
    deliveredTo: wantsEmail ? user.email : null,
  });
  let emailed = false;
  let emailError = false;
  if (wantsEmail) {
    try {
      emailed = await deliver(context.env, user.email, user.name, link.token);
    } catch {
      emailError = true;
    }
  }
  return {
    expiresAt: link.expiresAt,
    emailed,
    // Without delivered mail the administrator hands the link over; it is shown once.
    activationUrl: emailed ? null : activationUrl(context.env, link.token),
    emailError,
  };
}

activationRoutes.post("/api/admin/users", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const body = await readBody(context);
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || name.length === 0 || name.length > 128) {
    return context.json({ error: "이름과 올바른 이메일이 필요합니다." }, 400);
  }
  return auditStandaloneOperation(context.env, "identity.user.create", "/api/admin/users", async () => {
    const existing = await context.env.DB.prepare('SELECT id FROM "user" WHERE lower(email) = ? LIMIT 1')
      .bind(email).first<{ id: string }>();
    if (existing) {
      return { response: context.json({ error: "이미 등록된 이메일입니다." }, 409), actorUserId: actor.userId };
    }
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    await context.env.DB.prepare(
      `INSERT INTO "user" (id, name, email, emailVerified, createdAt, updatedAt, role)
       VALUES (?, ?, ?, 0, ?, ?, 'user')`,
    ).bind(id, name, email, now, now).run();
    const issued = await issueAndDeliver(context, actor.userId, { id, email, name }, body.sendEmail !== false);
    return {
      response: context.json({ user: { id, email, name }, activation: issued }, 201),
      actorUserId: actor.userId,
      targetUserId: id,
    };
  });
});

activationRoutes.post("/api/admin/users/:id/activation-link", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const body = await readBody(context);
  const userId = context.req.param("id");
  return auditStandaloneOperation(context.env, "identity.user.activation_link.issued", `/api/admin/users/${userId}/activation-link`, async () => {
    const user = await context.env.DB.prepare('SELECT id, email, name FROM "user" WHERE id = ? LIMIT 1')
      .bind(userId).first<{ id: string; email: string; name: string }>();
    if (!user) {
      return { response: context.json({ error: "사용자를 찾을 수 없습니다." }, 404), actorUserId: actor.userId };
    }
    const issued = await issueAndDeliver(context, actor.userId, user, body.sendEmail !== false);
    return { response: context.json({ activation: issued }), actorUserId: actor.userId, targetUserId: userId };
  });
});
