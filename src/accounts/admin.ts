/**
 * Account (tenant) administration: definition and membership lifecycle for
 * multi-account switching. Authorization mirrors the other admin routes
 * (administrator session plus exact configured origin) and every mutation is
 * audited. See docs/design/multi-accounts.md.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import {
  ACCOUNT_NAME_PATTERN,
  addAccountMember,
  countAccountAdmins,
  createAccount,
  deleteAccount,
  getAccount,
  isAccountMember,
  listAccountMembers,
  listAccounts,
  removeAccountMember,
  updateAccount,
  updateAccountMemberRole,
} from "./store";

export const accountAdminRoutes = new Hono<{ Bindings: Env }>();

export const ID_LIMIT = 128;
const DESCRIPTION_LIMIT = 512;
const USER_ID_LIMIT = 256;

function badRequest(context: Context<{ Bindings: Env }>, message: string): Response {
  return context.json({ error: message }, 400);
}

function isDescription(input: unknown): boolean {
  return typeof input === "string" && input.length <= DESCRIPTION_LIMIT &&
    !/[\u0000-\u0008\u000b-\u001f\u007f]/.test(input);
}

function toRole(input: unknown): "admin" | "member" {
  return input === "admin" ? "admin" : "member";
}

function isRole(input: unknown): boolean {
  return input === "admin" || input === "member";
}

accountAdminRoutes.use("/accounts", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});
accountAdminRoutes.use("/accounts/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

accountAdminRoutes.get("/accounts", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
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
  return context.json(await listAccounts(context.env, limit, cursor));
});

accountAdminRoutes.post("/accounts", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { name, description } = body as Record<string, unknown>;
  if (typeof name !== "string" || !ACCOUNT_NAME_PATTERN.test(name)) {
    return badRequest(context, "name must be 1-64 characters from [A-Za-z0-9_.-]");
  }
  if (description !== undefined && !isDescription(description)) {
    return badRequest(context, "description must be a short text without control characters");
  }
  return auditStandaloneOperation(context.env, "account.create", "/api/admin/accounts", async () => {
    try {
      const account = await createAccount(context.env, {
        name,
        description: typeof description === "string" ? description : "",
        creatorUserId: actor.userId,
      });
      if (!account) {
        return { response: Response.json({ error: "Account could not be created" }, { status: 500 }), actorUserId: actor.userId };
      }
      return {
        response: Response.json({ account }, { status: 201 }),
        actorUserId: actor.userId,
        targetUserId: account.id,
      };
    } catch (error) {
      // Only the unique NAME violation is a duplicate. A new NOT NULL or
      // CHECK constraint failing here must not masquerade as one, so the
      // error is witnessed and rethrown for the audited failure path.
      const message = error instanceof Error ? error.message : "";
      if (message.includes("UNIQUE constraint failed: accounts.name")) {
        return {
          response: Response.json({ error: "An account with this name already exists" }, { status: 409 }),
          actorUserId: actor.userId,
        };
      }
      throw error;
    }
  });
});

accountAdminRoutes.patch("/accounts/:id", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > ID_LIMIT) return context.json({ error: "Account not found" }, 400);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { name, description } = body as Record<string, unknown>;
  if (name === undefined && description === undefined) {
    return badRequest(context, "name or description is required");
  }
  if (name !== undefined && (typeof name !== "string" || !ACCOUNT_NAME_PATTERN.test(name))) {
    return badRequest(context, "name must be 1-64 characters from [A-Za-z0-9_.-]");
  }
  if (description !== undefined && !isDescription(description)) {
    return badRequest(context, "description must be a short text without control characters");
  }
  return auditStandaloneOperation(context.env, "account.update", context.req.path, async () => {
    try {
      const account = await updateAccount(context.env, id, {
        name: typeof name === "string" ? name : undefined,
        description: typeof description === "string" ? description : undefined,
      });
      if (!account) {
        return { response: Response.json({ error: "Account not found" }, { status: 404 }), actorUserId: actor.userId };
      }
      return {
        response: Response.json({ account }),
        actorUserId: actor.userId,
        targetUserId: id,
      };
    } catch (error) {
      // Only the unique name violation is a duplicate; everything else keeps
      // its audited failure path.
      const message = error instanceof Error ? error.message : "";
      if (message.includes("UNIQUE constraint failed: accounts.name")) {
        return {
          response: Response.json({ error: "An account with this name already exists" }, { status: 409 }),
          actorUserId: actor.userId,
        };
      }
      throw error;
    }
  });
});

accountAdminRoutes.patch("/accounts/:id/members/:userId", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id");
  const userId = context.req.param("userId");
  if (!accountId || accountId.length > ID_LIMIT || !userId || userId.length > USER_ID_LIMIT) {
    return context.json({ error: "Account not found" }, 404);
  }
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { role } = body as Record<string, unknown>;
  if (!isRole(role)) return badRequest(context, "role must be 'admin' or 'member'");
  const memberRole = toRole(role);
  return auditStandaloneOperation(context.env, "account.member.role.update", context.req.path, async () => {
    // Demoting the last admin would strand the account with no admin member;
    // guard against it before the write.
    if (memberRole === "member") {
      const membership = await isAccountMember(context.env, accountId, userId);
      if (membership === "admin" && (await countAccountAdmins(context.env, accountId)) === 1) {
        return {
          response: Response.json({ error: "Cannot demote the last admin member" }, { status: 409 }),
          actorUserId: actor.userId,
          targetUserId: userId,
        };
      }
    }
    const changed = await updateAccountMemberRole(context.env, accountId, userId, memberRole);
    if (!changed) {
      return { response: Response.json({ error: "Membership not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    return {
      response: Response.json({ membership: { accountId, userId, role: memberRole } }),
      actorUserId: actor.userId,
      targetUserId: userId,
    };
  });
});

accountAdminRoutes.get("/accounts/:id", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const id = context.req.param("id");
  if (!id || id.length > ID_LIMIT) return context.json({ error: "Account not found" }, 404);
  const account = await getAccount(context.env, id);
  if (!account) return context.json({ error: "Account not found" }, 404);
  return context.json({ account, members: await listAccountMembers(context.env, id) });
});

accountAdminRoutes.delete("/accounts/:id", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > ID_LIMIT) return context.json({ error: "Account not found" }, 404);
  return auditStandaloneOperation(context.env, "account.delete", context.req.path, async () => {
    const removed = await deleteAccount(context.env, id);
    if (!removed) {
      return { response: Response.json({ error: "Account not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    return { response: Response.json({ deleted: true }), actorUserId: actor.userId, targetUserId: id };
  });
});

accountAdminRoutes.post("/accounts/:id/members", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id");
  if (!accountId || accountId.length > ID_LIMIT) return context.json({ error: "Account not found" }, 404);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object") return context.json({ error: "Invalid body" }, 400);
  const { userId, role } = body as Record<string, unknown>;
  if (typeof userId !== "string" || userId.length < 1 || userId.length > USER_ID_LIMIT) {
    return badRequest(context, "userId is required");
  }
  const memberRole = toRole(role);
  const account = await getAccount(context.env, accountId);
  if (!account) return context.json({ error: "Account not found" }, 404);
  const user = await context.env.DB.prepare('SELECT id FROM "user" WHERE id = ?').bind(userId).first();
  if (!user) return context.json({ error: "User not found" }, 404);
  return auditStandaloneOperation(context.env, "account.member.add", context.req.path, async () => {
    const added = await addAccountMember(context.env, accountId, userId, memberRole, actor.userId);
    if (!added) {
      return { response: Response.json({ error: "User is already a member" }, { status: 409 }), actorUserId: actor.userId };
    }
    return {
      response: Response.json({ membership: { accountId, userId, role: memberRole, grantedBy: actor.userId } }, { status: 201 }),
      actorUserId: actor.userId,
      targetUserId: userId,
    };
  });
});

accountAdminRoutes.delete("/accounts/:id/members/:userId", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id");
  const userId = context.req.param("userId");
  if (!accountId || accountId.length > ID_LIMIT || !userId || userId.length > USER_ID_LIMIT) {
    return context.json({ error: "Account not found" }, 404);
  }
  return auditStandaloneOperation(context.env, "account.member.remove", context.req.path, async () => {
    // Removing the last admin member strands the account with nobody able to
    // administer it; guard the same way the demotion path does.
    if ((await isAccountMember(context.env, accountId, userId)) === "admin" &&
        (await countAccountAdmins(context.env, accountId)) === 1) {
      return {
        response: Response.json({ error: "Cannot remove the last admin member" }, { status: 409 }),
        actorUserId: actor.userId,
        targetUserId: userId,
      };
    }
    const removed = await removeAccountMember(context.env, accountId, userId);
    if (!removed) {
      return { response: Response.json({ error: "Membership not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    return { response: Response.json({ deleted: true }), actorUserId: actor.userId, targetUserId: userId };
  });
});
