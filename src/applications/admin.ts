/**
 * Administrator routes for the application registry: application lifecycle
 * (disabled creation, deliberate enablement) and provider binding. Every
 * mutation is audited; authorization mirrors the other admin routes.
 */

import { appAudience, notifyUsers } from "../users/notifications";
import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { WORKPASS_SLUG } from "../auth/workpass";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import {
  createApplication,
  deleteApplication,
  getApplication,
  listApplications,
  setApplicationEnabled,
  updateApplication,
  validateApplicationInput,
  validateBindingReference,
} from "./store";
import { removeProvider, syncProvider } from "./integration-routes";
import {
  deleteApplicationIcon,
  iconDisplayPath,
  iconObjectKey,
  ICON_MAX_BYTES,
  putApplicationIcon,
} from "./icons";

export const applicationAdminRoutes = new Hono<{ Bindings: Env }>();

applicationAdminRoutes.use("/applications*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

applicationAdminRoutes.get("/applications", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const applications = await listApplications(context.env);
  return context.json({ applications: applications.map((app) => ({ ...app, protected: app.slug === WORKPASS_SLUG })) });
});

applicationAdminRoutes.get("/applications/:slug", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const application = await getApplication(context.env, context.req.param("slug"));
  if (!application) return applicationNotFound(context);
  return context.json({ application: { ...application, protected: application.slug === WORKPASS_SLUG } });
});

applicationAdminRoutes.post("/applications", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const input = await readInput(context, "create");
  if (input instanceof Response) return input;
  return auditStandaloneOperation(context.env, "app.create", "/api/admin/applications", async () => {
    let application;
    try {
      application = await createApplication(context.env, input.input as import("./store").ValidatedApplicationInput, actor.userId);
    } catch (error) {
      return badInput(context, actor.userId, error);
    }
    if (!application) {
      return { response: Response.json({ error: "An application with this slug already exists" }, { status: 409 }), actorUserId: actor.userId };
    }
    return {
      response: Response.json({ application }, { status: 201 }),
      actorUserId: actor.userId,
      targetUserId: application.slug,
    };
  });
});

applicationAdminRoutes.patch("/applications/:slug", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const slug = context.req.param("slug");
  const input = await readInput(context, "patch");
  if (input instanceof Response) return input;
  if (slug === WORKPASS_SLUG && (input.input.name !== undefined || input.input.launchUrl !== undefined || input.input.hideFromDashboard === true)) {
    return context.json({ error: "WorkPass Dashboard의 이름, 주소, 표시 여부는 바꿀 수 없습니다." }, 409);
  }
  return auditStandaloneOperation(context.env, "app.update", context.req.path, async () => {
    let application;
    try {
      // The protocol is immutable: a protocol change would orphan the
      // stored app:<slug> gate policy and any issued-URL semantics.
      if (input.input.protocol !== undefined && input.input.protocol !== (await getApplication(context.env, slug))?.protocol) {
        return { response: Response.json({ error: "protocol is immutable" }, { status: 400 }), actorUserId: actor.userId };
      }
      const updates = { ...input.input };
      delete updates.protocol;
      delete updates.slug;
      application = await updateApplication(context.env, slug, updates);
    } catch (error) {
      return badInput(context, actor.userId, error);
    }
    if (!application) return { response: await applicationNotFound(context), actorUserId: actor.userId };
    return {
      response: Response.json({ application }),
      actorUserId: actor.userId,
      targetUserId: application.slug,
    };
  });
});

/** Enable/disable: the same two-step lifecycle language as the other registries. */
applicationAdminRoutes.post("/applications/:slug/enable", async (context) =>
  await withEnabled(context, "app.enable", true));
applicationAdminRoutes.post("/applications/:slug/disable", async (context) =>
  await withEnabled(context, "app.disable", false));

async function withEnabled(
  context: Context<{ Bindings: Env }>,
  eventType: string,
  enabled: boolean,
): Promise<Response> {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const slug = context.req.param("slug");
  if (!slug) return context.json({ error: "Application not found" }, 404);
  if (slug === WORKPASS_SLUG && !enabled) {
    return context.json({ error: "WorkPass Dashboard는 끌 수 없습니다." }, 409);
  }
  return auditStandaloneOperation(context.env, eventType, context.req.path, async () => {
    const application = await getApplication(context.env, slug);
    if (!application) return { response: await applicationNotFound(context), actorUserId: actor.userId };
    // The protocol provider follows the app; turning on fails with the reason
    // (for example an unusable SAML certificate) and leaves the app off.
    const providerError = await syncProvider(context.env, application, enabled);
    if (providerError && enabled) {
      return { response: Response.json({ error: providerError }, { status: 409 }), actorUserId: actor.userId, targetUserId: slug };
    }
    const changed = await setApplicationEnabled(context.env, slug, enabled);
    if (changed && enabled && !application.enabled) {
      await notifyUsers(context.env, await appAudience(context.env, slug), { kind: "app_assigned", title: "새 앱을 사용할 수 있습니다", body: `${application.name}을(를) 이제 열 수 있습니다.`, link: "/" });
    }
    return {
      response: changed
        ? Response.json({ application: { ...application, enabled } })
        : Response.json({ error: "Application not found" }, { status: 404 }),
      actorUserId: actor.userId,
      targetUserId: slug,
    };
  });
}

applicationAdminRoutes.post("/applications/:slug/icon", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const slug = context.req.param("slug");
  if (!slug) return context.json({ error: "Application not found" }, 404);
  return auditStandaloneOperation(context.env, "app.icon.upload", context.req.path, async () => {
    const contentTypeHeader = context.req.header("content-type") ?? "";
    if (!contentTypeHeader.toLowerCase().includes("multipart/form-data")) {
      return {
        response: Response.json({ error: "Submit the icon as multipart/form-data with a `file` field" }, { status: 400 }),
        actorUserId: actor.userId,
      };
    }
    if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) {
      return { response: Response.json({ error: "Invalid origin" }, { status: 403 }), actorUserId: actor.userId };
    }
    const form = await context.req.formData().catch(() => null);
    const file = form?.get("file");
    if (!(file instanceof File) || file.size === 0) {
      // Origin check passed; still rejected before any read (fail-closed).
      return {
        response: Response.json({ error: "The `file` field with the icon is required" }, { status: 400 }),
        actorUserId: actor.userId,
      };
    }
    const application = await getApplication(context.env, slug);
    if (!application) {
      return { response: await applicationNotFound(context), actorUserId: actor.userId };
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    const stored = await putApplicationIcon(context.env, application, bytes);
    if (!stored) {
      return {
        response: Response.json(
          { error: `The icon must be png/jpeg/webp/gif/svg at most ${ICON_MAX_BYTES} bytes` },
          { status: 400 },
        ),
        actorUserId: actor.userId,
        targetUserId: slug,
      };
    }
    return {
      response: Response.json({
        icon: { path: iconDisplayPath({ slug, iconKey: iconObjectKey(slug), iconUrl: null }), contentType: stored.contentType },
      }),
      actorUserId: actor.userId,
      targetUserId: slug,
    };
  });
});

applicationAdminRoutes.delete("/applications/:slug/icon", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const slug = context.req.param("slug");
  if (!slug) return context.json({ error: "Application not found" }, 404);
  return auditStandaloneOperation(context.env, "app.icon.delete", context.req.path, async () => {
    const application = await getApplication(context.env, slug);
    if (!application) {
      return { response: await applicationNotFound(context), actorUserId: actor.userId };
    }
    const removed = await deleteApplicationIcon(context.env, slug);
    if (!removed) {
      return { response: await applicationNotFound(context), actorUserId: actor.userId, targetUserId: slug };
    }
    return {
      response: Response.json({ deleted: true }),
      actorUserId: actor.userId,
      targetUserId: slug,
    };
  });
});

applicationAdminRoutes.delete("/applications/:slug", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const slug = context.req.param("slug");
  if (!slug) return context.json({ error: "Application not found" }, 404);
  if (slug === WORKPASS_SLUG) {
    return context.json({ error: "WorkPass Dashboard는 삭제할 수 없습니다." }, 409);
  }
  return auditStandaloneOperation(context.env, "app.delete", context.req.path, async () => {
    const existing = await getApplication(context.env, slug);
    if (!existing) return { response: await applicationNotFound(context), actorUserId: actor.userId };
    let provider;
    try {
      provider = await removeProvider(context.env, existing);
    } catch (error) {
      console.error("Application provider removal failed", error);
      return { response: Response.json({ error: "연결된 서비스 제공자를 삭제하지 못했습니다. 앱은 삭제되지 않았습니다." }, { status: 500 }), actorUserId: actor.userId, targetUserId: slug };
    }
    if (existing.iconKey) {
      await deleteApplicationIcon(context.env, slug).catch(() => undefined);
    }
    const removed = await deleteApplication(context.env, slug);
    return {
      response: removed
        ? Response.json({ deleted: true, ...provider })
        : Response.json({ error: "Application not found" }, { status: 404 }),
      actorUserId: actor.userId,
      targetUserId: slug,
    };
  });
});

async function applicationNotFound(context: Context<{ Bindings: Env }>): Promise<Response> {
  return context.json({ error: "Application not found" }, 404);
}

function badInput(context: Context<{ Bindings: Env }>, actorUserId: string, error: unknown) {
  console.error("Application input rejected", {
    name: error instanceof Error ? error.name : "UnknownError",
  });
  return {
    response: Response.json(
      { error: error instanceof Error ? error.message : "Invalid application" },
      { status: 400 },
    ),
    actorUserId,
  };
}

/** Parse and pre-validate the JSON body once for the audited operation. */
async function readInput(
  context: Context<{ Bindings: Env }>,
  mode: "create" | "patch",
): Promise<{ input: Partial<import("./store").ValidatedApplicationInput> } | Response> {
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  try {
    return { input: await validateApplicationInput(context.env, body as Record<string, unknown>, mode) };
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "Invalid application" }, 400);
  }
}

// Kept exported for the create path: the binding reference check happens
// inside createApplication/updateApplication via finalizeProtocol.
export { validateBindingReference };
