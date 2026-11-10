/**
 * Administrator routes for runtime settings. The response carries the whole
 * screen definition (groups, labels, ranges, options) so the admin console
 * renders from it and holds no setting knowledge of its own.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { SETTING_GROUPS, normalizeSettingValue, settingDefinition } from "./registry";
import { clearSetting, resolveSettings, saveSetting } from "./store";

export const settingsRoutes = new Hono<{ Bindings: Env }>();

settingsRoutes.use("/settings*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

settingsRoutes.get("/settings", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const resolved = await resolveSettings(context.env);
  return context.json({
    groups: Object.entries(SETTING_GROUPS).map(([id, group]) => ({ id, ...group })),
    settings: resolved.map(({ definition, value, source, updatedBy, updatedAt }) => ({
      key: definition.key,
      group: definition.group,
      label: definition.label,
      description: definition.description,
      type: definition.type,
      options: definition.type === "enum" ? definition.options : undefined,
      min: definition.type === "int" || definition.type === "number" ? definition.min : undefined,
      max: definition.type === "int" || definition.type === "number" ? definition.max : undefined,
      maxLength: definition.type === "text" ? definition.maxLength : undefined,
      step: definition.type === "number" ? definition.step : undefined,
      unit: definition.type === "int" ? definition.unit : undefined,
      default: definition.default,
      value,
      source,
      updatedBy,
      updatedAt,
    })),
  });
});

settingsRoutes.put("/settings/:key", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const key = context.req.param("key");
  const definition = settingDefinition(key);
  if (!definition) return context.json({ error: "알 수 없는 설정입니다." }, 404);

  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "요청을 읽을 수 없습니다." }, 400);
  }
  let value: string;
  try {
    value = normalizeSettingValue(definition, (body as { value?: unknown } | null)?.value);
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "잘못된 값입니다." }, 400);
  }

  // Switching device-risk checks on without the server key would reject every
  // login, administrators included.
  if (key === "fingerprint.mode" && value !== "disabled" && !context.env.FINGERPRINT_SERVER_API_KEY) {
    return context.json({ error: "서버 키(FINGERPRINT_SERVER_API_KEY)가 설정되지 않아 켤 수 없습니다." }, 409);
  }

  // Enforcement rejects any login without a verified device event. Before it
  // goes on, prove the browser side works for the person turning it on.
  if (key === "fingerprint.mode" && value === "enforce") {
    if (!context.env.FINGERPRINT_PUBLIC_API_KEY?.trim()) {
      return context.json({ error: "공개 키(FINGERPRINT_PUBLIC_API_KEY)가 없어 브라우저가 기기를 확인할 수 없습니다. 강제로 바꾸면 모두 로그인하지 못합니다." }, 409);
    }
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const proof = await context.env.DB.prepare(
      "SELECT 1 AS ok FROM fingerprint_risk_decisions WHERE user_id = ? AND event_id IS NOT NULL AND occurred_at > ? LIMIT 1",
    ).bind(actor.userId, since).first().catch(() => null);
    if (!proof) {
      return context.json({
        error: "이 관리자 계정으로 기기 확인에 성공한 기록이 없습니다. 먼저 '관찰'로 바꾸고 로그아웃한 뒤 다시 로그인해 확인되는지 본 다음에 강제로 바꾸세요.",
      }, 409);
    }
  }

  return auditStandaloneOperation(context.env, "admin.setting.updated", `/api/admin/settings/${key}`, async () => {
    await saveSetting(context.env, key, value, actor.userId);
    return { response: context.json({ key, value }), actorUserId: actor.userId, targetUserId: key };
  });
});

settingsRoutes.delete("/settings/:key", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const key = context.req.param("key");
  if (!settingDefinition(key)) return context.json({ error: "알 수 없는 설정입니다." }, 404);
  return auditStandaloneOperation(context.env, "admin.setting.reset", `/api/admin/settings/${key}`, async () => {
    await clearSetting(context.env, key);
    return { response: context.json({ key, reset: true }), actorUserId: actor.userId, targetUserId: key };
  });
});
