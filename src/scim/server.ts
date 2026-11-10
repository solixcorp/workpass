/**
 * Inbound SCIM 2.0 (RFC 7644) server: workforce systems (an HR platform or a
 * parent identity provider) provision users INTO this platform. This is the
 * deliberate counterpart of the outbound SCIM client, and it preserves the
 * platform's credential posture: a provisioned user has NO password, so a
 * system-created account cannot sign in until an operator sets one.
 *
 * Bearer-token protected (INBOUND_SCIM_BEARER_TOKEN with
 * ENABLE_INBOUND_SCIM=true), audited per operation, and deletes deactivate
 * (ban) rather than destroy: the user remains for audit and re-activation.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { constantTimeTokenMatches } from "../security/tokens";
import { auditStandaloneOperation } from "../audit/store";
import {
  getObjectAttributes,
  parseAttributesInput,
  setObjectAttributes,
  type AttributeValue,
} from "../objects/attributes";
import { scheduleScimAttributeSync } from "./executor";
import { emitAttributeChangedEvent } from "../ssf/attribute-events";

export const inboundScimRoutes = new Hono<{ Bindings: Env }>();

const USER_SCHEMAS = ["urn:ietf:params:scim:schemas:core:2.0:User"];
const LIST_SCHEMAS = ["urn:ietf:params:scim:api:messages:2.0:ListResponse"];
/**
 * Custom object attributes travel as one SCIM extension schema: the schema
 * URN carries a flat object of primitive values validated by the same
 * bounds as the admin attributes API.
 */
const CUSTOM_ATTRIBUTES_URN = "urn:solixcorp:scim:1.0:CustomAttributes";

interface ScimUserRow {
  id: string;
  name: string;
  email: string;
  username: string | null;
  /** SQLite boolean: 0/1 from (banned IS NULL OR banned = 0). */
  active: number;
}

function scimConfig(env: Env): { ok: boolean } {
  return {
    ok: env.ENABLE_INBOUND_SCIM === "true" &&
      typeof env.INBOUND_SCIM_BEARER_TOKEN === "string" &&
      env.INBOUND_SCIM_BEARER_TOKEN.length >= 32,
  };
}

function unauthorized(context: Context<{ Bindings: Env }>): Response {
  context.header("WWW-Authenticate", 'Bearer realm="scim"');
  return Response.json(
    { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "401", detail: "Authentication required" },
    { status: 401 },
  );
}

async function requireScimToken(context: Context<{ Bindings: Env }>): Promise<Response | null> {
  if (!scimConfig(context.env)) {
    return Response.json(
      { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "503", detail: "Inbound SCIM is not configured" },
      { status: 503 },
    );
  }
  const authorization = context.req.header("authorization") ?? "";
  const provided = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : "";
  if (!provided || !constantTimeTokenMatches(provided, context.env.INBOUND_SCIM_BEARER_TOKEN!)) {
    return unauthorized(context);
  }
  return null;
}

function userToScim(row: ScimUserRow, attributes?: Record<string, AttributeValue>): Record<string, unknown> {
  const hasAttributes = attributes !== undefined && Object.keys(attributes).length > 0;
  return {
    schemas: hasAttributes ? [...USER_SCHEMAS, CUSTOM_ATTRIBUTES_URN] : USER_SCHEMAS,
    id: row.id,
    userName: row.username ?? row.email,
    name: { formatted: row.name },
    emails: [{ value: row.email, primary: true, type: "work" }],
    active: row.active === 1,
    ...(hasAttributes ? { [CUSTOM_ATTRIBUTES_URN]: attributes } : {}),
    meta: { resourceType: "User" },
  };
}

/** Extract a validated attribute set from the extension, or null to leave it untouched. */
function parseCustomAttributes(body: Record<string, unknown>): { ok: true; attributes: Record<string, AttributeValue> | null } | { ok: false; error: string } {
  if (!Object.hasOwn(body, CUSTOM_ATTRIBUTES_URN)) return { ok: true, attributes: null };
  const parsed = parseAttributesInput(body[CUSTOM_ATTRIBUTES_URN]);
  if (!parsed.ok) return parsed;
  return { ok: true, attributes: parsed.attributes };
}

async function loadUser(env: Env, id: string): Promise<ScimUserRow | null> {
  const row = await env.DB.prepare(
    `SELECT id, name, email, username, (banned IS NULL OR banned = 0) AS active
     FROM "user" WHERE id = ? LIMIT 1`,
  ).bind(id).first<ScimUserRow>();
  return row ?? null;
}

async function findUserByEmail(env: Env, email: string): Promise<ScimUserRow | null> {
  const row = await env.DB.prepare(
    `SELECT id, name, email, username, (banned IS NULL OR banned = 0) AS active
     FROM "user" WHERE lower(email) = lower(?) LIMIT 1`,
  ).bind(email).first<ScimUserRow>();
  return row ?? null;
}

type ScimErrorStatus = "400" | "404" | "409";

function scimError(status: ScimErrorStatus, detail: string): Response {
  return Response.json(
    { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status, detail },
    { status: Number(status) },
  );
}

interface ParsedNewUser {
  email: string;
  name: string;
  username: string | null;
}

function parseNewUser(body: Record<string, unknown>): ParsedNewUser | null {
  const userName = typeof body.userName === "string" ? body.userName.trim() : "";
  const nameObject = (body.name ?? {}) as { formatted?: unknown; givenName?: unknown; familyName?: unknown };
  const name = typeof nameObject.formatted === "string" && nameObject.formatted.trim()
    ? nameObject.formatted.trim()
    : typeof body.displayName === "string" && body.displayName.trim() ? body.displayName.trim() : "";
  const emails = Array.isArray(body.emails) ? body.emails : [];
  const primaryEmail = emails
    .map((entry) => (entry && typeof entry === "object" && typeof (entry as { value?: unknown }).value === "string"
      ? ((entry as { value: string }).value.trim())
      : typeof entry === "string" ? entry.trim() : ""))
    .find((value) => value.length > 0) ?? "";
  const email = primaryEmail || userName;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !name) return null;
  return { email, name, username: userName || null };
}

function audit(context: Context<{ Bindings: Env }>, operation: string, path: string, body: () => Promise<{ response: Response; actorUserId?: string; targetUserId?: string }>): Promise<Response> {
  return auditStandaloneOperation(context.env, operation, path, body);
}

const SCIM_PATH = "/scim/v2";

inboundScimRoutes.use(`${SCIM_PATH}/*`, async (context, next) => {
  // RFC 7644 §4: discovery endpoints are unauthenticated.
  if (!new URL(context.req.url).pathname.startsWith(`${SCIM_PATH}/ServiceProviderConfig`)) {
    const denied = await requireScimToken(context);
    if (denied) return denied;
  }
  context.header("Cache-Control", "no-store");
  return next();
});

inboundScimRoutes.get(`${SCIM_PATH}/ServiceProviderConfig`, (context) =>
  context.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    patch: { supported: true },
    filter: { supported: true, maxResults: 200 },
    bulk: { supported: false, maxOperations: 0, maxSize: 0 },
    authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "Static bearer token" }],
  }));

inboundScimRoutes.get(`${SCIM_PATH}/Users`, async (context) => {
  const url = new URL(context.req.url);
  const filter = url.searchParams.get("filter") ?? "";
  const eqMatch = /^userName\s+eq\s+"([^"]+)"$/.exec(filter.trim()) ?? /^emails?\s+eq\s+"([^"]+)"$/.exec(filter.trim());
  const startIndex = Math.max(1, Number(url.searchParams.get("startIndex") ?? "1") || 1);
  const count = Math.min(200, Math.max(1, Number(url.searchParams.get("count") ?? "100") || 100));
  const rows = eqMatch
    ? await context.env.DB.prepare(
      `SELECT id, name, email, username, (banned IS NULL OR banned = 0) AS active
       FROM "user" WHERE lower(username) = lower(?) OR lower(email) = lower(?)
       ORDER BY createdAt ASC LIMIT ? OFFSET ?`,
    ).bind(eqMatch[1]!, eqMatch[1]!, count, startIndex - 1).all<ScimUserRow>()
    : await context.env.DB.prepare(
      `SELECT id, name, email, username, (banned IS NULL OR banned = 0) AS active
       FROM "user" ORDER BY createdAt ASC LIMIT ? OFFSET ?`,
    ).bind(count, startIndex - 1).all<ScimUserRow>();
  return context.json({
    schemas: LIST_SCHEMAS,
    totalResults: rows.results.length,
    startIndex,
    itemsPerPage: count,
    Resources: await Promise.all(rows.results.map(async (row) => {
      const { attributes } = await getObjectAttributes(context.env, "user", row.id);
      return userToScim(row, attributes);
    })),
  });
});

inboundScimRoutes.get(`${SCIM_PATH}/Users/:id`, async (context) => {
  const row = await loadUser(context.env, context.req.param("id"));
  if (!row) return scimError("404", "User not found");
  const { attributes } = await getObjectAttributes(context.env, "user", row.id);
  return context.json(userToScim(row, attributes));
});

inboundScimRoutes.post(`${SCIM_PATH}/Users`, async (context) => {
  let body: Record<string, unknown>;
  try {
    body = (await context.req.json()) as Record<string, unknown>;
  } catch {
    return scimError("400", "The request body must be a SCIM User resource");
  }
  const parsed = parseNewUser(body);
  if (!parsed) {
    return scimError("400", "userName (an email) and a display name are required");
  }
  const attributes = parseCustomAttributes(body);
  if (!attributes.ok) return scimError("400", attributes.error);
  return audit(context, "scim.inbound.user.create", `${SCIM_PATH}/Users`, async () => {
    const existing = await findUserByEmail(context.env, parsed.email);
    if (existing) {
      return { response: scimError("409", "A user with this email already exists") };
    }
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    await context.env.DB.prepare(
      `INSERT INTO "user" (id, name, email, emailVerified, createdAt, updatedAt, username, role)
       VALUES (?, ?, ?, 0, ?, ?, ?, "user")`,
    ).bind(id, parsed.name, parsed.email, now, now, parsed.username).run();
    if (attributes.attributes !== null) {
      await setObjectAttributes(context.env, "user", id, attributes.attributes, null);
      await scheduleScimAttributeSync(context.env, id).catch(() => undefined);
      await emitAttributeChangedEvent(context.env, {
        userId: id,
        objectType: "user",
        objectId: id,
        changedKeys: Object.keys(attributes.attributes),
      }).catch(() => undefined);
    }
    const row = await loadUser(context.env, id);
    const stored = await getObjectAttributes(context.env, "user", id);
    // A provisioned user must NEVER carry a credential from the source system.
    const response = Response.json(userToScim(row!, stored.attributes), { status: 201 });
    return { response, targetUserId: id };
  });
});

inboundScimRoutes.put(`${SCIM_PATH}/Users/:id`, async (context) => {
  let body: Record<string, unknown>;
  try {
    body = (await context.req.json()) as Record<string, unknown>;
  } catch {
    return scimError("400", "The request body must be a SCIM User resource");
  }
  const parsed = parseNewUser(body);
  const active = typeof body.active === "boolean" ? body.active : null;
  const attributes = parseCustomAttributes(body);
  if (!attributes.ok) return scimError("400", attributes.error);
  return audit(context, "scim.inbound.user.put", `${SCIM_PATH}/Users/${context.req.param("id")}`, async () => {
    const row = await loadUser(context.env, context.req.param("id"));
    if (!row) return { response: scimError("404", "User not found") };
    if (parsed) {
      const clash = parsed.email.toLowerCase() !== row.email.toLowerCase()
        ? await findUserByEmail(context.env, parsed.email)
        : null;
      if (clash) return { response: scimError("409", "A user with this email already exists") };
    }
    const banned = active === false || (active === null && !row.active) ? 1 : 0;
    await context.env.DB.prepare(
      `UPDATE "user" SET name = ?, email = ?, banned = ?, updatedAt = ? WHERE id = ?`,
    ).bind(
      parsed?.name ?? row.name,
      parsed?.email ?? row.email,
      banned,
      new Date().toISOString(),
      row.id,
    ).run();
    if (attributes.attributes !== null) {
      // Full-resource semantics: the extension replaces the whole set (an
      // empty extension clears it, matching RFC 7644 full replacement).
      await setObjectAttributes(context.env, "user", row.id, attributes.attributes, null);
      await scheduleScimAttributeSync(context.env, row.id).catch(() => undefined);
    }
    const updated = await loadUser(context.env, row.id);
    const stored = await getObjectAttributes(context.env, "user", row.id);
    return { response: Response.json(userToScim(updated!, stored.attributes)), targetUserId: row.id };
  });
});

inboundScimRoutes.patch(`${SCIM_PATH}/Users/:id`, async (context) => {
  let body: { Operations?: Array<{ op?: unknown; path?: unknown; value?: unknown }> };
  try {
    body = (await context.req.json()) as typeof body;
  } catch {
    return scimError("400", "The request body must be a SCIM PatchOp");
  }
  return audit(context, "scim.inbound.user.patch", `${SCIM_PATH}/Users/${context.req.param("id")}`, async () => {
    const row = await loadUser(context.env, context.req.param("id"));
    if (!row) return { response: scimError("404", "User not found") };
    let active: boolean | null = null;
    let attributesPatch: Record<string, AttributeValue> | null | undefined = undefined;
    for (const operation of body.Operations ?? []) {
      if (operation.op !== "replace" && operation.op !== "Replace" && operation.op !== "remove" && operation.op !== "Remove") continue;
      if (operation.path === "active" && typeof operation.value === "boolean") {
        active = operation.value;
      } else if ((operation.path === undefined || operation.path === null) &&
        typeof (operation.value as { active?: unknown })?.active === "boolean") {
        active = (operation.value as { active: boolean }).active;
      } else if (operation.path === CUSTOM_ATTRIBUTES_URN) {
        if (operation.op === "remove" || operation.op === "Remove") {
          // Removing the extension clears the whole attribute set.
          attributesPatch = {};
        } else {
          const parsed = parseCustomAttributes({ [CUSTOM_ATTRIBUTES_URN]: operation.value });
          if (!parsed.ok) return { response: scimError("400", parsed.error) };
          attributesPatch = parsed.attributes;
        }
      }
    }
    if (active === null && attributesPatch === undefined) {
      return { response: scimError("400", "Only active replacement is supported") };
    }
    if (active !== null) {
      await context.env.DB.prepare(
        `UPDATE "user" SET banned = ?, updatedAt = ? WHERE id = ?`,
      ).bind(active ? 0 : 1, new Date().toISOString(), row.id).run();
    }
    if (attributesPatch !== undefined && attributesPatch !== null) {
      await setObjectAttributes(context.env, "user", row.id, attributesPatch, null);
      await scheduleScimAttributeSync(context.env, row.id).catch(() => undefined);
    }
    const updated = await loadUser(context.env, row.id);
    const stored = await getObjectAttributes(context.env, "user", row.id);
    return { response: Response.json(userToScim(updated!, stored.attributes)), targetUserId: row.id };
  });
});

// SCIM DELETE deactivates rather than destroys: the account is retained for
// audit history and can be re-activated by the same provisioning system.
inboundScimRoutes.delete(`${SCIM_PATH}/Users/:id`, async (context) => {
  return audit(context, "scim.inbound.user.delete", `${SCIM_PATH}/Users/${context.req.param("id")}`, async () => {
    const row = await loadUser(context.env, context.req.param("id"));
    if (!row) return { response: scimError("404", "User not found") };
    await context.env.DB.prepare(
      `UPDATE "user" SET banned = 1, updatedAt = ? WHERE id = ?`,
    ).bind(new Date().toISOString(), row.id).run();
    return { response: new Response(null, { status: 204 }), targetUserId: row.id };
  });
});
