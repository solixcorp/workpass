/**
 * Administration API for custom object attributes. The endpoint addresses an
 * object by its type and identifier, requires an administrator session and
 * the exact configured origin like every admin surface, and audits every
 * mutation. Reads are session-gated but not audited, matching the other admin
 * read routes.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { scheduleScimAttributeSync } from "../scim/executor";
import { emitAttributeChangedEvent } from "../ssf/attribute-events";
import {
  deleteObjectAttributes,
  getObjectAttributes,
  isObjectAttributeType,
  OBJECT_ATTRIBUTE_TYPES,
  attributeObjectExists,
  parseAttributesInput,
  setObjectAttributes,
  type ObjectAttributeType,
} from "./attributes";

export const objectAttributeRoutes = new Hono<{ Bindings: Env }>();

const OBJECT_ID_LIMIT = 128;

function badRequest(context: Context<{ Bindings: Env }>, message: string): Response {
  return context.json({ error: message }, 400);
}

/** Resolve the :objectType/:objectId pair or null (a response was sent). */
async function resolveObject(
  context: Context<{ Bindings: Env }>,
): Promise<{ type: ObjectAttributeType; objectId: string } | Response> {
  const rawType = context.req.param("objectType");
  const objectId = context.req.param("objectId");
  if (!rawType || !isObjectAttributeType(rawType)) {
    return context.json({ error: `objectType must be one of: ${OBJECT_ATTRIBUTE_TYPES.join(", ")}` }, 400);
  }
  if (!objectId || objectId.length === 0 || objectId.length > OBJECT_ID_LIMIT) {
    return context.json({ error: "Invalid objectId" }, 400);
  }
  return { type: rawType, objectId };
}

objectAttributeRoutes.use("/attributes/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

objectAttributeRoutes.get("/attributes/:objectType/:objectId", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const target = await resolveObject(context);
  if (target instanceof Response) return target;
  if (!(await attributeObjectExists(context.env, target.type, target.objectId))) {
    return context.json({ error: "Object not found" }, 404);
  }
  const current = await getObjectAttributes(context.env, target.type, target.objectId);
  return context.json({ objectType: target.type, objectId: target.objectId, ...current });
});

objectAttributeRoutes.put("/attributes/:objectType/:objectId", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const target = await resolveObject(context);
  if (target instanceof Response) return target;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const parsed = parseAttributesInput((body as Record<string, unknown>).attributes);
  if (!parsed.ok) return badRequest(context, parsed.error);
  return auditStandaloneOperation(context.env, "attributes.set", context.req.path, async () => {
    if (!(await attributeObjectExists(context.env, target.type, target.objectId))) {
      return { response: Response.json({ error: "Object not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    try {
      await setObjectAttributes(
        context.env,
        target.type,
        target.objectId,
        parsed.attributes,
        actor.userId,
      );
    } catch (error) {
      // Mirror the directory routes: only an expected storage failure path is
      // surfaced deliberately; everything else is rethrown for the audited
      // failure outcome.
      console.error("Failed to store object attributes", {
        objectType: target.type,
        errorName: error instanceof Error ? error.name : "UnknownError",
      });
      return {
        response: Response.json({ error: "Failed to store attributes" }, { status: 503 }),
        actorUserId: actor.userId,
      };
    }
    const stored = await getObjectAttributes(context.env, target.type, target.objectId);
    // Attribute changes propagate two ways: SCIM targets that already map
    // the user get a queued update op drained by the cron dispatcher, and
    // SSF recipients subscribed to the attribute-change URN get a SET event.
    if (target.type === "user") {
      const synced = await scheduleScimAttributeSync(context.env, target.objectId).catch(() => false);
      if (!synced) {
        console.warn("SCIM attribute propagation not queued", { userId: target.objectId });
      }
    }
    await emitAttributeChangedEvent(context.env, {
      objectType: target.type,
      objectId: target.objectId,
      changedKeys: Object.keys(parsed.attributes),
    }).catch(() => undefined);
    return {
      response: Response.json({ objectType: target.type, objectId: target.objectId, ...stored }),
      actorUserId: actor.userId,
      targetUserId: target.objectId,
    };
  });
});

objectAttributeRoutes.delete("/attributes/:objectType/:objectId", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const target = await resolveObject(context);
  if (target instanceof Response) return target;
  return auditStandaloneOperation(context.env, "attributes.delete", context.req.path, async () => {
    if (!(await attributeObjectExists(context.env, target.type, target.objectId))) {
      return { response: Response.json({ error: "Object not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    const removed = await deleteObjectAttributes(context.env, target.type, target.objectId);
    if (removed && target.type === "user") {
      await scheduleScimAttributeSync(context.env, target.objectId).catch(() => undefined);
    }
    if (removed) {
      await emitAttributeChangedEvent(context.env, {
        objectType: target.type,
        objectId: target.objectId,
        changedKeys: [],
      }).catch(() => undefined);
    }
    return {
      response: removed
        ? Response.json({ deleted: true })
        : Response.json({ deleted: true, attributesExisted: false }),
      actorUserId: actor.userId,
      targetUserId: target.objectId,
    };
  });
});
