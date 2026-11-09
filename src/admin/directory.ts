/**
 * Directory group administration: first-party group definitions and
 * membership with minimum personal data. Authorization mirrors the other
 * admin routes (administrator session plus exact configured origin) and
 * every mutation is audited. See docs/design/directory-groups.md.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";

export const directoryRoutes = new Hono<{ Bindings: Env }>();

const GROUP_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const DESCRIPTION_LIMIT = 512;
const ID_LIMIT = 128;


function badRequest(context: Context<{ Bindings: Env }>, message: string): Response {
  return context.json({ error: message }, 400);
}

directoryRoutes.use("/directory-groups", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});
directoryRoutes.use("/directory-groups/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

directoryRoutes.get("/directory-groups", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const query = new URL(context.req.url).searchParams;
  const rawLimit = query.get("limit");
  if (rawLimit !== null && (!/^[0-9]+$/.test(rawLimit) || Number(rawLimit) < 1 || Number(rawLimit) > 100)) {
    return context.json({ error: "limit must be an integer between 1 and 100" }, 400);
  }
  const cursor = query.get("cursor");
  if (cursor !== null && (cursor.length === 0 || cursor.length > ID_LIMIT)) {
    return context.json({ error: "Invalid cursor" }, 400);
  }
  const limit = rawLimit === null ? 50 : Number(rawLimit);
  const result = await context.env.DB.prepare(
    `SELECT id, name, description, created_by AS createdBy, created_at AS createdAt
     FROM directory_groups WHERE (? IS NULL OR id > ?) ORDER BY id ASC LIMIT ?`,
  ).bind(cursor, cursor, limit + 1).all<{
    id: string; name: string; description: string; createdBy: string; createdAt: string;
  }>();
  const rows = result.results.slice(0, limit);
  return context.json({
    groups: rows,
    nextCursor: result.results.length > limit ? rows.at(-1)?.id ?? null : null,
  });
});

directoryRoutes.post("/directory-groups", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { name, description } = body as Record<string, unknown>;
  if (typeof name !== "string" || !GROUP_NAME_PATTERN.test(name)) {
    return badRequest(context, "name must be 1-64 characters from [A-Za-z0-9_.-]");
  }
  if (description !== undefined && (typeof description !== "string" || description.length > DESCRIPTION_LIMIT || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(description))) {
    return badRequest(context, "description must be a short text without control characters");
  }
  return auditStandaloneOperation(context.env, "directory.group.create", "/api/admin/directory-groups", async () => {
    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    try {
      await context.env.DB.prepare(
        `INSERT INTO directory_groups (id, name, description, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(id, name, typeof description === "string" ? description : "", actor.userId, now, now).run();
      return {
        response: Response.json({
          group: { id, name, description: typeof description === "string" ? description : "", createdBy: actor.userId, createdAt: now },
        }, { status: 201 }),
        actorUserId: actor.userId,
        targetUserId: id,
      };
    } catch (error) {
      // Only the unique NAME violation is a duplicate. A new NOT NULL or
      // CHECK constraint failing here must not masquerade as one, so the
      // error is witnessed and rethrown for the audited failure path.
      const message = error instanceof Error ? error.message : "";
      if (message.includes("UNIQUE constraint failed: directory_groups.name")) {
        return {
          response: Response.json({ error: "A group with this name already exists" }, { status: 409 }),
          actorUserId: actor.userId,
        };
      }
      throw error;
    }
  });
});

directoryRoutes.get("/directory-groups/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  if (!id || id.length > ID_LIMIT) return context.json({ error: "Group not found" }, 404);
  const group = await context.env.DB.prepare(
    `SELECT id, name, description, created_by AS createdBy, created_at AS createdAt
     FROM directory_groups WHERE id = ?`,
  ).bind(id).first<{ id: string; name: string; description: string; createdBy: string; createdAt: string }>();
  if (!group) return context.json({ error: "Group not found" }, 404);
  const memberships = await context.env.DB.prepare(
    `SELECT user_id AS userId, granted_by AS grantedBy, granted_at AS grantedAt
     FROM directory_group_members WHERE group_id = ? ORDER BY granted_at ASC, user_id ASC LIMIT 500`,
  ).bind(id).all<{ userId: string; grantedBy: string; grantedAt: string }>();
  return context.json({ group, members: memberships.results });
});

directoryRoutes.delete("/directory-groups/:id", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > ID_LIMIT) return context.json({ error: "Group not found" }, 404);
  return auditStandaloneOperation(context.env, "directory.group.delete", context.req.path, async () => {
    const removed = await context.env.DB.batch([
      context.env.DB.prepare("DELETE FROM directory_group_members WHERE group_id = ?").bind(id),
      context.env.DB.prepare("DELETE FROM directory_groups WHERE id = ?").bind(id),
    ]);
    if (removed[1]!.meta.changes !== 1) {
      return { response: Response.json({ error: "Group not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    return { response: Response.json({ deleted: true }), actorUserId: actor.userId, targetUserId: id };
  });
});

directoryRoutes.post("/directory-groups/:id/members", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const groupId = context.req.param("id");
  if (!groupId || groupId.length > ID_LIMIT) return context.json({ error: "Group not found" }, 404);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object") return context.json({ error: "Invalid body" }, 400);
  const { userId } = body as Record<string, unknown>;
  if (typeof userId !== "string" || userId.length < 1 || userId.length > 256) {
    return badRequest(context, "userId is required");
  }
  const group = await context.env.DB.prepare("SELECT id FROM directory_groups WHERE id = ?").bind(groupId).first();
  if (!group) return context.json({ error: "Group not found" }, 404);
  const user = await context.env.DB.prepare('SELECT id FROM "user" WHERE id = ?').bind(userId).first();
  if (!user) return context.json({ error: "User not found" }, 404);
  return auditStandaloneOperation(context.env, "directory.member.add", context.req.path, async () => {
    const now = new Date().toISOString();
    const inserted = await context.env.DB.prepare(
      `INSERT OR IGNORE INTO directory_group_members (group_id, user_id, granted_by, granted_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(groupId, userId, actor.userId, now).run();
    if (inserted.meta.changes !== 1) {
      return { response: Response.json({ error: "User is already a member" }, { status: 409 }), actorUserId: actor.userId };
    }
    return {
      response: Response.json({ membership: { groupId, userId, grantedBy: actor.userId, grantedAt: now } }, { status: 201 }),
      actorUserId: actor.userId,
      targetUserId: userId,
    };
  });
});

directoryRoutes.delete("/directory-groups/:id/members/:userId", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const groupId = context.req.param("id");
  const userId = context.req.param("userId");
  if (!groupId || groupId.length > ID_LIMIT || !userId || userId.length > 256) {
    return context.json({ error: "Group not found" }, 404);
  }
  return auditStandaloneOperation(context.env, "directory.member.remove", context.req.path, async () => {
    const removed = await context.env.DB.prepare(
      "DELETE FROM directory_group_members WHERE group_id = ? AND user_id = ?",
    ).bind(groupId, userId).run();
    if (removed.meta.changes !== 1) {
      return { response: Response.json({ error: "Membership not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    return { response: Response.json({ deleted: true }), actorUserId: actor.userId, targetUserId: userId };
  });
});
