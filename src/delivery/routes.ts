/** Administrator control of how e-mail and SMS are sent. Secrets are accepted, sealed, and never returned. */

import { Hono } from "hono";
import { auditStandaloneOperation } from "../audit/store";
import type { Env } from "../env";
import { selectedMailProviderId, isMailProviderEnabled } from "../mail/provider";
import { sendTransactionEmail } from "../mail/send";
import { requireAdministrator } from "../security/authorization";
import { organizationName } from "../settings/registry";
import { selectedSmsProvider, sendSms, smsAvailable } from "../sms/provider";
import { allFields, CATALOG, COMMON_FIELDS, providerSpec, type DeliveryKind } from "./catalog";
import { deliveryOverrides, loadDelivery, removeDelivery, saveDelivery } from "./store";

export const deliveryRoutes = new Hono<{ Bindings: Env }>();

deliveryRoutes.use("/delivery/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

const kindOf = (value: string): DeliveryKind | null => (value === "email" || value === "sms" ? value : null);
const CONTROL = /[\u0000-\u001f\u007f]/;

/** What the deployment itself (not the console) provides for a kind. */
function deploymentProvider(env: Env, kind: DeliveryKind): { provider: string | null; available: boolean } {
  try {
    if (kind === "email") {
      const id = selectedMailProviderId(env);
      return { provider: id, available: Boolean(env.INVITATION_EMAIL_WEBHOOK_URL) || isMailProviderEnabled(env) };
    }
  } catch {
    return { provider: null, available: false };
  }
  return { provider: selectedSmsProvider(env), available: smsAvailable(env) };
}

async function view(env: Env, kind: DeliveryKind) {
  const stored = await loadDelivery(env, kind, true);
  if (stored) {
    const fields = allFields(kind, stored.provider);
    const effective = { ...env, ...(await deliveryOverrides(env)) } as Env;
    return {
      source: "console" as const,
      provider: stored.provider,
      values: stored.values,
      secretsSet: Object.fromEntries(fields.filter((f) => f.secret).map((f) => [f.key, Boolean(stored.secrets[f.key])])),
      available: deploymentProvider(effective, kind).available,
      updatedAt: stored.updatedAt,
    };
  }
  const deployment = deploymentProvider(env, kind);
  return { source: deployment.provider ? ("deployment" as const) : ("none" as const), provider: deployment.provider, values: {}, secretsSet: {}, available: deployment.available, updatedAt: null };
}

deliveryRoutes.get("/delivery", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  return context.json({
    email: await view(context.env, "email"),
    sms: await view(context.env, "sms"),
    catalog: { email: CATALOG.email, sms: CATALOG.sms, common: COMMON_FIELDS },
    canStoreSecrets: Boolean(context.env.AEAD_SEALING_KEY),
  });
});

deliveryRoutes.put("/delivery/:kind", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const kind = kindOf(context.req.param("kind"));
  if (!kind) return context.json({ error: "알 수 없는 종류입니다." }, 404);
  const body = (await context.req.json().catch(() => null)) as { provider?: unknown; values?: unknown; secrets?: unknown } | null;
  const provider = typeof body?.provider === "string" ? body.provider : "";
  const spec = providerSpec(kind, provider);
  if (!spec) return context.json({ error: "지원하지 않는 공급자입니다." }, 400);
  const fields = allFields(kind, provider);
  const input = (body?.values && typeof body.values === "object" ? body.values : {}) as Record<string, unknown>;
  const secretInput = (body?.secrets && typeof body.secrets === "object" ? body.secrets : {}) as Record<string, unknown>;
  const previous = await loadDelivery(context.env, kind, true);
  const keep = previous && previous.provider === provider ? previous : null;

  const values: Record<string, string> = {};
  const secrets: Record<string, string> = {};
  for (const field of fields) {
    if (field.secret) {
      const given = secretInput[field.key];
      // Omitted keeps what is stored; an empty string or null removes it.
      const next = given === undefined ? keep?.secrets[field.key] ?? "" : typeof given === "string" ? given.trim() : "";
      if (next.length > 1024 || CONTROL.test(next)) return context.json({ error: `${field.label} 값이 올바르지 않습니다.` }, 400);
      if (next) secrets[field.key] = next;
      else if (field.required) return context.json({ error: `${field.label}을(를) 입력하세요.` }, 400);
    } else {
      const raw = input[field.key];
      const next = typeof raw === "string" ? raw.trim() : typeof raw === "number" ? String(raw) : "";
      if (next.length > 512 || CONTROL.test(next)) return context.json({ error: `${field.label} 값이 올바르지 않습니다.` }, 400);
      if (!next && field.required) return context.json({ error: `${field.label}을(를) 입력하세요.` }, 400);
      if (field.type === "select" && next && !field.options?.some((o) => o.value === next)) return context.json({ error: `${field.label} 값이 올바르지 않습니다.` }, 400);
      if (next) values[field.key] = next;
    }
  }
  if (kind === "email") {
    const mailbox = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
    if (!mailbox.test(values.from ?? "")) return context.json({ error: "보내는 주소 형식이 올바르지 않습니다." }, 400);
    if (values.replyTo && !mailbox.test(values.replyTo)) return context.json({ error: "회신 주소 형식이 올바르지 않습니다." }, 400);
    if (values.port && !(Number.isInteger(Number(values.port)) && Number(values.port) >= 1 && Number(values.port) <= 65535)) return context.json({ error: "포트는 1에서 65535 사이여야 합니다." }, 400);
    if (values.region && !/^[a-z0-9-]{4,30}$/.test(values.region)) return context.json({ error: "리전 형식이 올바르지 않습니다." }, 400);
    if (values.endpoint && !/^https:\/\/[^\s]+$/.test(values.endpoint)) return context.json({ error: "엔드포인트는 https 주소여야 합니다." }, 400);
  } else {
    if (provider === "webhook" && !/^https:\/\/[^\s]+$/.test(values.url ?? "")) return context.json({ error: "웹훅 주소는 https 주소여야 합니다." }, 400);
    if (provider !== "webhook" && !/^[+0-9A-Za-z -]{3,40}$/.test(values.from ?? "")) return context.json({ error: "발신번호 형식이 올바르지 않습니다." }, 400);
  }
  if (Object.keys(secrets).length > 0 && !context.env.AEAD_SEALING_KEY) {
    return context.json({ error: "서버에 AEAD_SEALING_KEY가 설정되어 있지 않아 비밀값을 저장할 수 없습니다. 배포 설정에 키를 먼저 넣으세요." }, 409);
  }
  return auditStandaloneOperation(context.env, `delivery.${kind}.update`, context.req.path, async () => {
    await saveDelivery(context.env, { kind, provider, values, secrets, adminId: admin.userId });
    return { response: Response.json({ saved: true }), actorUserId: admin.userId, targetUserId: null };
  });
});

/** Go back to what the deployment itself provides. */
deliveryRoutes.delete("/delivery/:kind", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const kind = kindOf(context.req.param("kind"));
  if (!kind) return context.json({ error: "알 수 없는 종류입니다." }, 404);
  return auditStandaloneOperation(context.env, `delivery.${kind}.reset`, context.req.path, async () => {
    const removed = await removeDelivery(context.env, kind);
    return { response: removed ? Response.json({ reset: true }) : Response.json({ error: "저장된 설정이 없습니다." }, { status: 404 }), actorUserId: admin.userId, targetUserId: null };
  });
});

/** Send one real message with what is configured now, so a wrong key shows up here and not at someone's sign-in. */
deliveryRoutes.post("/delivery/:kind/test", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const kind = kindOf(context.req.param("kind"));
  if (!kind) return context.json({ error: "알 수 없는 종류입니다." }, 404);
  const body = (await context.req.json().catch(() => null)) as { to?: unknown } | null;
  const to = typeof body?.to === "string" ? body.to.trim() : "";
  if (kind === "email" && !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(to)) return context.json({ error: "받을 이메일 주소를 확인하세요." }, 400);
  if (kind === "sms" && !/^\+[1-9][0-9]{5,14}$/.test(to)) return context.json({ error: "받을 번호는 +821012345678 형식으로 넣으세요." }, 400);

  const stored = await loadDelivery(context.env, kind, true);
  const effective = { ...context.env, ...(await deliveryOverrides(context.env)) } as Env;
  let outcome: { ok: true } | { ok: false; error: string };
  try {
    if (kind === "email") {
      await sendTransactionEmail(effective, { to, subject: `[${organizationName(effective)}] 테스트 메일`, text: "관리자가 보낸 테스트 메일입니다. 이 메일이 보인다면 메일 발송 설정이 올바른 것입니다." });
    } else {
      await sendSms(effective, { to, text: `[${organizationName(effective)}] 테스트 문자입니다. 이 문자가 보인다면 SMS 설정이 올바른 것입니다.` });
    }
    outcome = { ok: true };
  } catch (error) {
    let message = error instanceof Error ? error.message : "발송하지 못했습니다.";
    // Provider answers can echo a credential back; never pass one on.
    for (const secret of Object.values(stored?.secrets ?? {})) if (secret.length >= 4) message = message.split(secret).join("•••");
    outcome = { ok: false, error: message.slice(0, 400) };
  }
  await auditStandaloneOperation(context.env, `delivery.${kind}.test`, context.req.path, async () => ({
    response: Response.json({}), actorUserId: admin.userId, targetUserId: null,
  })).catch(() => null);
  return context.json(outcome);
});
