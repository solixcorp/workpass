import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import {
  createSamlServiceProvider,
  getSamlServiceProvider,
  setSamlServiceProviderEnabled,
  validateSamlServiceProvider,
} from "./service-providers";
import { importSamlServiceProviderTrustedKey } from "./certificates";
import { requireAdministrator } from "../security/authorization";

export const samlAdminRoutes = new Hono<{ Bindings: Env }>();

samlAdminRoutes.use("/saml-service-providers/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

samlAdminRoutes.use("/saml-service-providers", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

samlAdminRoutes.get("/saml-service-providers", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  const query = new URL(context.req.url).searchParams;
  const rawLimit = query.get("limit");
  if (rawLimit !== null && (!/^[0-9]+$/.test(rawLimit) || Number(rawLimit) < 1 || Number(rawLimit) > 100)) {
    return context.json({ error: "limit must be an integer between 1 and 100" }, 400);
  }
  const cursor = query.get("cursor");
  if (cursor !== null && (!cursor || cursor.length > 128)) return context.json({ error: "Invalid cursor" }, 400);
  const limit = rawLimit === null ? 50 : Number(rawLimit);
  const result = await context.env.DB.prepare(
    `SELECT id, entity_id, acs_url, enabled FROM saml_service_providers
     WHERE (? IS NULL OR id > ?) ORDER BY id ASC LIMIT ?`,
  ).bind(cursor, cursor, limit + 1).all<{ id: string; entity_id: string; acs_url: string; enabled: number }>();
  const rows = result.results.slice(0, limit);
  return context.json({
    providers: rows.map((row) => ({ id: row.id, entityId: row.entity_id, acsUrl: row.acs_url, enabled: row.enabled === 1 })),
    nextCursor: result.results.length > limit ? rows.at(-1)?.id ?? null : null,
  });
});

samlAdminRoutes.get("/saml-service-providers/:id", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  const provider = await getSamlServiceProvider(context.env, context.req.param("id"));
  if (!provider) return context.json({ error: "Service provider not found" }, 404);
  return context.json({ provider });
});

samlAdminRoutes.post("/saml-service-providers/:id/enable", async (context) => {
  return setProviderEnabled(context, true, "saml.service_provider.enable");
});

samlAdminRoutes.post("/saml-service-providers/:id/disable", async (context) => {
  return setProviderEnabled(context, false, "saml.service_provider.disable");
});

samlAdminRoutes.delete("/saml-service-providers/:id", async (context) => {
  const id = context.req.param("id");
  if (!id || id.length > 128) return context.json({ error: "Invalid service provider" }, 400);
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  return auditStandaloneOperation(context.env, "saml.service_provider.delete", `/api/admin/saml-service-providers/${id}/delete`, async () => {
    // A disabled registration can be removed outright; an enabled one must be
    // disabled first so its retirement is a deliberate two-step action.
    const provider = await getSamlServiceProvider(context.env, id);
    if (!provider) return { response: Response.json({ error: "Service provider not found" }, { status: 404 }), actorUserId: adminSession.userId };
    if (provider.enabled) {
      return { response: Response.json({ error: "Disable the service provider before deleting it" }, { status: 409 }), actorUserId: adminSession.userId, targetUserId: id };
    }
    const removed = await context.env.DB.prepare(
      "DELETE FROM saml_service_providers WHERE id = ? AND enabled = 0",
    ).bind(id).run();
    return {
      response: removed.meta.changes === 1
        ? Response.json({ deleted: true })
        : Response.json({ error: "Service provider not found or enabled" }, { status: 409 }),
      actorUserId: adminSession.userId,
      targetUserId: id,
    };
  });
});

samlAdminRoutes.post("/saml-service-providers", async (context) => {
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid request" }, 400);
  const value = body as Record<string, unknown>;
  if (typeof value.entityId !== "string" || typeof value.acsUrl !== "string" || typeof value.signingCertificate !== "string") {
    return context.json({ error: "entityId, acsUrl and signingCertificate are required" }, 400);
  }
  const provider = { id: crypto.randomUUID(), entityId: value.entityId, acsUrl: value.acsUrl, signingCertificate: value.signingCertificate };
  try { validateSamlServiceProvider({ ...provider, enabled: false }); } catch { return context.json({ error: "Invalid service provider" }, 400); }
  // The console asks for the certificate to be proven usable now, so an app is
  // never created that could not be turned on.
  if (value.verifyCertificate === true) {
    try {
      await importSamlServiceProviderTrustedKey(provider.signingCertificate);
    } catch {
      return context.json({ error: "서명 인증서를 쓸 수 없습니다. RSA 인증서(PEM)가 맞는지 확인하세요." }, 400);
    }
  }
  return auditStandaloneOperation(context.env, "saml.service_provider.create", "/api/admin/saml-service-providers", async () => {
    const inserted = await createSamlServiceProvider(context.env, provider);
    return {
      response: inserted
        ? Response.json({ provider: { ...provider, enabled: false } }, { status: 201 })
        : Response.json({ error: "Service provider already exists" }, { status: 409 }),
      actorUserId: adminSession.userId,
    };
  });
});

/**
 * Enablement flips the flag only after the stored certificate imports into a
 * usable verify key; disabling is always allowed. Both are audited and
 * require an administrator session from the exact trusted origin.
 */
async function setProviderEnabled(
  context: Context<{ Bindings: Env }>,
  enabled: boolean,
  eventType: string,
): Promise<Response> {
  const id = context.req.param("id");
  if (!id || id.length > 128) return context.json({ error: "Invalid service provider" }, 400);
  const adminSession = await requireAdministrator(context);
  if (adminSession instanceof Response) return adminSession;
  const provider = await getSamlServiceProvider(context.env, id);
  if (!provider) return context.json({ error: "Service provider not found" }, 404);
  if (enabled) {
    try {
      await importSamlServiceProviderTrustedKey(provider.signingCertificate);
    } catch {
      return context.json(
        { error: "The stored signing certificate is not a usable RSA certificate" },
        400,
      );
    }
  }
  return auditStandaloneOperation(context.env, eventType, `/api/admin/saml-service-providers/${id}/${enabled ? "enable" : "disable"}`, async () => {
    const changed = await setSamlServiceProviderEnabled(context.env, id, enabled);
    return {
      response: changed
        ? Response.json({ provider: { id: provider.id, entityId: provider.entityId, enabled } })
        : Response.json({ error: "Service provider not found" }, { status: 404 }),
      actorUserId: adminSession.userId,
      targetUserId: id,
    };
  });
}
