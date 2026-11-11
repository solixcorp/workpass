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
import { transactionEmailAvailable, sendTransactionEmail } from "../mail/send";
import {
  ACCOUNT_NAME_PATTERN,
  addAccountMember,
  countAccountAdmins,
  createAccount,
  createAccountInvitation,
  deleteAccount,
  getAccount,
  getAccountInvitation,
  getInvitationById,
  isAccountMember,
  listAccountInvitations,
  listAccountMembers,
  listAccounts,
  markAccountInvitationDelivered,
  removeAccountMember,
  revokeAccountInvitation,
  revokeInvitationById,
  reissueInvitation,
  INVITATION_DEFAULT_TTL_DAYS,
  INVITATION_MAX_TTL_DAYS,
  updateAccount,
  updateAccountMemberRole,
} from "./store";
import type { AccountInvitationRow, AccountRow } from "./store";

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

function emailAddress(input: unknown): input is string {
  return typeof input === "string" && input.trim().length <= 256 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.trim());
}

async function deliverInvitation(env: Env, invitation: AccountInvitationRow, account: AccountRow, to: string): Promise<boolean> {
  try {
    await sendTransactionEmail(env, {
      to, subject: `You are invited to join ${account.name}`,
      text: [`You have been invited to join the account "${account.name}".`, "",
        "To accept, sign in at the identity provider and redeem this invitation code:", "", invitation.token, "",
        `Membership role: ${invitation.role}`, `The invitation expires at ${invitation.expiresAt}.`].join("\n"),
    });
    await markAccountInvitationDelivered(env, invitation.token, to);
    return true;
  } catch (error) {
    console.error("Invitation email delivery failed", { name: error instanceof Error ? error.name : "UnknownError" });
    return false;
  }
}

function issuedInvitation(invitation: AccountInvitationRow) {
  return { id: invitation.id, token: invitation.token, accountId: invitation.accountId, role: invitation.role,
    createdAt: invitation.createdAt, expiresAt: invitation.expiresAt };
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
  return context.json({ ...await listAccounts(context.env, limit, cursor), limit });
});

accountAdminRoutes.post("/accounts", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { name: rawName, description: rawDescription } = body as Record<string, unknown>;
  const name = typeof rawName === "string" ? rawName.trim() : rawName;
  const description = typeof rawDescription === "string" ? rawDescription.trim() : rawDescription;
  if (typeof name !== "string" || !ACCOUNT_NAME_PATTERN.test(name)) {
    return badRequest(context, "name must be 1-128 characters from [A-Za-z0-9_.-]");
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
  const { name: rawName, description: rawDescription } = body as Record<string, unknown>;
  const name = typeof rawName === "string" ? rawName.trim() : rawName;
  const description = typeof rawDescription === "string" ? rawDescription.trim() : rawDescription;
  if (name === undefined && description === undefined) {
    return badRequest(context, "name or description is required");
  }
  if (name !== undefined && (typeof name !== "string" || !ACCOUNT_NAME_PATTERN.test(name))) {
    return badRequest(context, "name must be 1-128 characters from [A-Za-z0-9_.-]");
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

accountAdminRoutes.post("/accounts/:id/invitations/:token/deliver", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id");
  const token = context.req.param("token");
  if (!accountId || accountId.length > ID_LIMIT || !token || token.length === 0 || token.length > 256) {
    return context.json({ error: "Invitation not found" }, 404);
  }
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { to } = body as Record<string, unknown>;
  if (typeof to !== "string" || to.length === 0 || to.length > 256 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to.trim())) {
    return badRequest(context, "to must be an email address");
  }
  if (!transactionEmailAvailable(context.env)) {
    return context.json({ error: "Transactional email is not configured" }, 503);
  }
  const recipient = to.trim();
  return auditStandaloneOperation(context.env, "account.invitation.email", context.req.path, async () => {
    const invitation = await getAccountInvitation(context.env, token);
    if (!invitation || invitation.accountId !== accountId || invitation.consumedAt !== null || invitation.revokedAt !== null) {
      return { response: Response.json({ error: "Invitation not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    if (invitation.expiresAt <= new Date().toISOString()) {
      return { response: Response.json({ error: "The invitation is expired" }, { status: 409 }), actorUserId: actor.userId };
    }
    const account = await getAccount(context.env, accountId);
    if (!account) {
      return { response: Response.json({ error: "Invitation not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    if (!await deliverInvitation(context.env, invitation, account, recipient)) {
      return {
        response: Response.json({ error: "Invitation email delivery failed" }, { status: 502 }),
        actorUserId: actor.userId,
        targetUserId: accountId,
      };
    }
    const updated = await getAccountInvitation(context.env, token);
    return {
      response: Response.json({
        invitation: updated && {
          tokenPrefix: `${invitation.token.slice(0, 6)}…`,
          accountId: updated.accountId,
          deliverTo: updated.deliverTo,
          deliveredAt: updated.deliveredAt,
        },
      }),
      actorUserId: actor.userId,
      targetUserId: accountId,
    };
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

accountAdminRoutes.post("/accounts/:id/invitations", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id");
  if (!accountId || accountId.length > ID_LIMIT) return context.json({ error: "Account not found" }, 404);
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { role, ttlDays, email } = body as Record<string, unknown>;
  if (role !== undefined && !isRole(role)) return badRequest(context, "role must be 'admin' or 'member'");
  if (email !== undefined && !emailAddress(email)) return badRequest(context, "email must be an email address");
  if (email !== undefined && !transactionEmailAvailable(context.env)) return context.json({ error: "Transactional email is not configured" }, 503);
  const memberRole = toRole(role);
  const parsedTtl = ttlDays === undefined ? INVITATION_DEFAULT_TTL_DAYS : ttlDays;
  if (typeof parsedTtl !== "number" || !Number.isSafeInteger(parsedTtl) || parsedTtl < 1 || parsedTtl > INVITATION_MAX_TTL_DAYS) {
    return badRequest(context, `ttlDays must be an integer between 1 and ${INVITATION_MAX_TTL_DAYS}`);
  }
  const account = await getAccount(context.env, accountId);
  if (!account) return context.json({ error: "Account not found" }, 404);
  return auditStandaloneOperation(context.env, "account.invitation.create", context.req.path, async () => {
    const invitation = await createAccountInvitation(context.env, {
      accountId, role: memberRole, ttlDays: parsedTtl, createdBy: actor.userId,
    });
    const delivered = typeof email === "string" ? await deliverInvitation(context.env, invitation, account, email.trim()) : undefined;
    // The full token is returned exactly once; the list view masks it.
    return {
      response: Response.json({
        invitation: issuedInvitation(invitation), ...(delivered === undefined ? {} : { delivered }),
      }, { status: 201 }),
      actorUserId: actor.userId,
      targetUserId: accountId,
    };
  });
});

accountAdminRoutes.get("/accounts/:id/invitations", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const accountId = context.req.param("id");
  if (!accountId || accountId.length > ID_LIMIT) return context.json({ error: "Account not found" }, 404);
  const account = await getAccount(context.env, accountId);
  if (!account) return context.json({ error: "Account not found" }, 404);
  const invitations = await listAccountInvitations(context.env, accountId);
  const now = new Date().toISOString();
  return context.json({
    invitations: invitations.map((invitation) => ({
      id: invitation.id,
      tokenPrefix: `${invitation.token.slice(0, 6)}…`,
      accountId: invitation.accountId,
      role: invitation.role,
      createdBy: invitation.createdBy,
      createdAt: invitation.createdAt,
      expiresAt: invitation.expiresAt,
      status: invitation.revokedAt !== null ? "revoked" : invitation.consumedAt !== null ? "accepted" : invitation.expiresAt <= now ? "expired" : "pending",
      deliverTo: invitation.deliverTo,
      deliveredAt: invitation.deliveredAt,
    })),
  });
});

accountAdminRoutes.delete("/accounts/:id/invitations/by-id/:invitationId", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id"), id = context.req.param("invitationId");
  if (accountId.length > ID_LIMIT || id.length > ID_LIMIT) return context.json({ error: "Invitation not found" }, 404);
  return auditStandaloneOperation(context.env, "account.invitation.revoke", context.req.path, async () => {
    const invitation = await getInvitationById(context.env, accountId, id);
    if (!invitation) return { response: Response.json({ error: "Invitation not found" }, { status: 404 }), actorUserId: actor.userId };
    const revoked = await revokeInvitationById(context.env, accountId, id);
    return { response: revoked ? Response.json({ revoked: true }) : Response.json({ error: "Invitation already accepted or revoked" }, { status: 409 }), actorUserId: actor.userId, targetUserId: accountId };
  });
});

accountAdminRoutes.post("/accounts/:id/invitations/by-id/:invitationId/reissue", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id"), id = context.req.param("invitationId");
  if (accountId.length > ID_LIMIT || id.length > ID_LIMIT) return context.json({ error: "Invitation not found" }, 404);
  let body: unknown;
  try { const text = await context.req.text(); body = text.trim() ? JSON.parse(text) : {}; } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const { deliverTo } = body as Record<string, unknown>;
  if (deliverTo !== undefined && !emailAddress(deliverTo)) return badRequest(context, "deliverTo must be an email address");
  if (deliverTo !== undefined && !transactionEmailAvailable(context.env)) return context.json({ error: "Transactional email is not configured" }, 503);
  return auditStandaloneOperation(context.env, "account.invitation.reissue", context.req.path, async () => {
    const old = await getInvitationById(context.env, accountId, id);
    if (!old) return { response: Response.json({ error: "Invitation not found" }, { status: 404 }), actorUserId: actor.userId };
    const account = await getAccount(context.env, accountId);
    if (!account) return { response: Response.json({ error: "Invitation not found" }, { status: 404 }), actorUserId: actor.userId };
    const invitation = await reissueInvitation(context.env, old, actor.userId);
    if (!invitation) return { response: Response.json({ error: "Invitation already accepted or revoked" }, { status: 409 }), actorUserId: actor.userId };
    const delivered = typeof deliverTo === "string" ? await deliverInvitation(context.env, invitation, account, deliverTo.trim()) : undefined;
    return { response: Response.json({ invitation: issuedInvitation(invitation), ...(delivered === undefined ? {} : { delivered }) }, { status: 201 }), actorUserId: actor.userId, targetUserId: accountId };
  });
});

accountAdminRoutes.delete("/accounts/:id/invitations/:token", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const accountId = context.req.param("id");
  const token = context.req.param("token");
  if (!accountId || accountId.length > ID_LIMIT || !token || token.length === 0 || token.length > 256) {
    return context.json({ error: "Invitation not found" }, 404);
  }
  return auditStandaloneOperation(context.env, "account.invitation.revoke", context.req.path, async () => {
    const invitation = await getAccountInvitation(context.env, token);
    if (!invitation || invitation.accountId !== accountId || invitation.consumedAt !== null || invitation.revokedAt !== null) {
      return { response: Response.json({ error: "Invitation not found" }, { status: 404 }), actorUserId: actor.userId };
    }
    const revoked = await revokeAccountInvitation(context.env, token);
    return {
      response: revoked
        ? Response.json({ revoked: true })
        : Response.json({ error: "Invitation not found" }, { status: 404 }),
      actorUserId: actor.userId,
      targetUserId: accountId,
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
