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
