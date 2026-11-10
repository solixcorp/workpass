/**
 * Applications: the unified application registry, authentik-style. One row
 * covers a plain bookmark app (no binding, launch URL only) or a backed
 * protocol app whose binding references its registered provider (SAML SP
 * entity id, WS-Fed realm, OIDC client id, SWA origin). Visibility on the
 * user surface is gated by the "app:<slug>" access-policy subject: with no
 * policy row every signed-in user sees the app, exactly like authentik's
 * empty-binding default.
 */

import type { Env } from "../env";
import { evaluateAppAccess, loadAppAccessPolicy } from "../access/policies";

export const APPLICATION_PROTOCOLS = ["bookmark", "saml", "wsfed", "oidc", "swa"] as const;
export type ApplicationProtocol = (typeof APPLICATION_PROTOCOLS)[number];

export interface ApplicationRow {
  id: string;
  slug: string;
  name: string;
  description: string;
  protocol: ApplicationProtocol;
  binding: string | null;
  launchUrl: string | null;
  /** Optional icon: an https URL (favicon-style small image). */
  iconUrl: string | null;
  /** R2 object key of an uploaded icon; takes precedence over icon_url. */
  iconKey: string | null;
  /** Optional dashboard grouping label (authentik's application group). */
  categoryGroup: string | null;
  hideFromDashboard: boolean;
  enabled: boolean;
  createdBy: string;
  createdAt: string;
}

const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const NAME_LIMIT = 128;
const DESCRIPTION_LIMIT = 512;
const BINDING_LIMIT = 2000;
// Control characters (except tab) are never allowed in user-visible text.
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;

export interface ValidatedApplicationInput {
  slug: string;
  name: string;
  description: string;
  protocol: ApplicationProtocol;
  binding: string | null;
  launchUrl: string | null;
  iconUrl: string | null;
  categoryGroup: string | null;
  hideFromDashboard: boolean;
}

/**
 * Validate a create/patch payload into field values. Throws with a precise
 * message the admin route surfaces as 400.
 */
export async function validateApplicationInput(
  env: Env,
  input: {
    slug?: unknown;
    name?: unknown;
    description?: unknown;
    protocol?: unknown;
    binding?: unknown;
    launchUrl?: unknown;
    iconUrl?: unknown;
    categoryGroup?: unknown;
    hideFromDashboard?: unknown;
  },
  mode: "create" | "patch",
): Promise<Partial<ValidatedApplicationInput>> {
  const result: Partial<ValidatedApplicationInput> = {};

  if (input.slug !== undefined || mode === "create") {
    const slug = input.slug === undefined ? "" : input.slug;
    if (typeof slug !== "string" || !SLUG_PATTERN.test(slug)) {
      throw new Error("slug must be 1-64 characters from [a-z0-9-] starting with a letter or digit");
    }
    result.slug = slug;
  }

  if (input.name !== undefined || mode === "create") {
    const name = input.name === undefined ? "" : input.name;
    if (typeof name !== "string" || name.trim().length === 0 || name.trim().length > NAME_LIMIT || CONTROL.test(name)) {
      throw new Error(`name must be 1-${NAME_LIMIT} characters without control characters`);
    }
    result.name = name.trim();
  }

  if (input.description !== undefined) {
    const description = input.description === null ? "" : input.description;
    if (typeof description !== "string" || description.length > DESCRIPTION_LIMIT || CONTROL.test(description)) {
      throw new Error(`description must be at most ${DESCRIPTION_LIMIT} characters without control characters`);
    }
    result.description = description;
  }

  if (input.protocol !== undefined || mode === "create") {
    const protocol = input.protocol === undefined ? "" : input.protocol;
    if (typeof protocol !== "string" || !(APPLICATION_PROTOCOLS as readonly string[]).includes(protocol)) {
      throw new Error(`protocol must be one of: ${APPLICATION_PROTOCOLS.join(", ")}`);
    }
    result.protocol = protocol as ApplicationProtocol;
  }

  if (input.binding !== undefined) {
    const binding = input.binding === null || input.binding === "" ? null : input.binding;
    if (binding !== null && (typeof binding !== "string" || binding.length > BINDING_LIMIT || CONTROL.test(binding))) {
      throw new Error(`binding must be at most ${BINDING_LIMIT} characters without control characters`);
    }
    result.binding = binding;
  }

  if (input.launchUrl !== undefined) {
    const launchUrl = input.launchUrl === null || input.launchUrl === "" ? null : input.launchUrl;
    if (launchUrl !== null) {
      if (typeof launchUrl !== "string") throw new Error("launchUrl must be a string or null");
      try {
        const url = new URL(launchUrl);
        if (url.protocol !== "https:" || url.username || url.password || url.hash) {
          throw new Error("launchUrl must be an https URL without credentials, query or fragment");
        }
        if (launchUrl.length > 2048) throw new Error("launchUrl must be at most 2048 characters");
      } catch (error) {
        if (error instanceof Error && error.message.startsWith("launchUrl")) throw error;
        throw new Error("launchUrl must be a valid https URL");
      }
    }
    result.launchUrl = launchUrl;
  }

  if (input.iconUrl !== undefined) {
    const iconUrl = input.iconUrl === null || input.iconUrl === "" ? null : input.iconUrl;
    if (iconUrl !== null) {
      if (typeof iconUrl !== "string") throw new Error("iconUrl must be a string or null");
      try {
        const url = new URL(iconUrl);
        if (url.protocol !== "https:" || url.username || url.password || url.hash) {
          throw new Error("iconUrl must be an https URL without credentials, query or fragment");
        }
        if (iconUrl.length > 2048) throw new Error("iconUrl must be at most 2048 characters");
      } catch (error) {
        if (error instanceof Error && error.message.startsWith("iconUrl")) throw error;
        throw new Error("iconUrl must be a valid https URL");
      }
    }
    result.iconUrl = iconUrl;
  }

  if (input.categoryGroup !== undefined) {
    const categoryGroup = input.categoryGroup === null || input.categoryGroup === "" ? null : input.categoryGroup;
    if (categoryGroup !== null && (typeof categoryGroup !== "string" || categoryGroup.trim().length === 0 || categoryGroup.length > 64 || CONTROL.test(categoryGroup))) {
      throw new Error("categoryGroup must be at most 64 characters without control characters");
    }
    result.categoryGroup = categoryGroup;
  }

  if (input.hideFromDashboard !== undefined) {
    result.hideFromDashboard = input.hideFromDashboard === true;
  }

  return result;
}

/** The binding must reference an existing registered provider for its protocol. */
export async function validateBindingReference(env: Env, protocol: ApplicationProtocol, binding: string): Promise<boolean> {
  try {
    if (protocol === "saml") {
      return (await env.DB.prepare("SELECT id FROM saml_service_providers WHERE entity_id = ?").bind(binding).first()) !== null;
    }
    if (protocol === "wsfed") {
      return (await env.DB.prepare("SELECT id FROM wsfed_relying_parties WHERE realm = ?").bind(binding).first()) !== null;
    }
    if (protocol === "swa") {
      return (await env.DB.prepare("SELECT id FROM swa_applications WHERE origin = ?").bind(binding).first()) !== null;
    }
    if (protocol === "oidc") {
      return (await env.DB.prepare("SELECT clientId FROM oauthClient WHERE clientId = ?").bind(binding).first()) !== null;
    }
    return false;
  } catch {
    // A missing provider table is as good as a missing binding reference.
    return false;
  }
}

/** Create an application. Disabled at birth, like every other registry. */
export async function createApplication(
  env: Env,
  input: ValidatedApplicationInput,
  createdBy: string,
): Promise<ApplicationRow | null> {
  const protocol = await finalizeProtocol(env, input);
  const now = new Date().toISOString();
  const row: ApplicationRow = {
    id: crypto.randomUUID(),
    slug: input.slug,
    name: input.name,
    // Optional fields arrive undefined when the caller omits them; D1 rejects
    // undefined bindings, so every column gets an explicit default here.
    description: input.description ?? "",
    protocol,
    binding: input.binding ?? null,
    launchUrl: input.launchUrl ?? null,
    iconUrl: input.iconUrl ?? null,
    iconKey: null,
    categoryGroup: input.categoryGroup ?? null,
    hideFromDashboard: input.hideFromDashboard === true,
    enabled: false,
    createdBy,
    createdAt: now,
  };
  try {
    await env.DB.prepare(
      `INSERT INTO applications
         (id, slug, name, description, protocol, binding, launch_url, icon_url, category_group, hide_from_dashboard, enabled, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
    ).bind(
      row.id, row.slug, row.name, row.description, protocol, row.binding ?? null,
      row.launchUrl ?? null, row.iconUrl ?? null, row.categoryGroup ?? null,
      row.hideFromDashboard ? 1 : 0, row.createdBy, row.createdAt, now,
    ).run();
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("UNIQUE constraint failed: applications.slug")) return null;
    throw error;
  }
  return row;
}

/** Bookmarks may not bind; backed protocols must. */
async function finalizeProtocol(env: Env, input: Partial<ValidatedApplicationInput>): Promise<ApplicationProtocol> {
  const protocol = input.protocol!;
  if (protocol === "bookmark") {
    if (input.binding) throw new Error("A bookmark application must not declare a binding");
    if (!input.launchUrl) throw new Error("A bookmark application requires a launchUrl");
    return protocol;
  }
  if (!input.binding) throw new Error(`A ${protocol} application requires a binding reference`);
  if (!(await validateBindingReference(env, protocol, input.binding))) {
    throw new Error(`The ${protocol} binding reference is not a registered provider`);
  }
  return protocol;
}

export async function getApplication(env: Env, slug: string): Promise<ApplicationRow | null> {
  return await loadApplicationRow(env, "slug = ?", slug);
}

export async function listApplications(env: Env, limit = 200): Promise<ApplicationRow[]> {
  const rows = await env.DB.prepare(
    `SELECT id, slug, name, description, protocol, binding, launch_url AS launchUrl,
            icon_url AS iconUrl, icon_key AS iconKey, category_group AS categoryGroup,
            hide_from_dashboard AS hideRaw, enabled AS enabledRaw,
            created_by AS createdBy, created_at AS createdAt
     FROM applications ORDER BY name ASC, slug ASC LIMIT ?`,
  ).bind(limit).all<ApplicationRowRow>();
  return rows.results.map(rowToApplicationRow);
}

export async function updateApplication(
  env: Env,
  slug: string,
  updates: Partial<ValidatedApplicationInput>,
): Promise<ApplicationRow | null> {
  const existing = await loadApplicationRow(env, "slug = ?", slug);
  if (!existing) return null;
  const merged: Partial<ValidatedApplicationInput> = {
    protocol: existing.protocol,
    binding: updates.binding !== undefined ? updates.binding : existing.binding,
    name: updates.name ?? existing.name,
    description: updates.description ?? existing.description,
    launchUrl: updates.launchUrl !== undefined ? updates.launchUrl : existing.launchUrl,
    hideFromDashboard: updates.hideFromDashboard ?? existing.hideFromDashboard,
  };
  const protocol = await finalizeProtocol(env, merged);
  const result = await env.DB.prepare(
    `UPDATE applications SET name = ?, description = ?, binding = ?, launch_url = ?,
       hide_from_dashboard = ?, updated_at = ? WHERE slug = ?`,
  ).bind(
    merged.name!, merged.description ?? "", merged.binding ?? null, merged.launchUrl ?? null,
    (merged.hideFromDashboard ?? false) ? 1 : 0, new Date().toISOString(), slug,
  ).run();
  if (result.meta.changes !== 1) return null;
  return await getApplication(env, slug);
}

export async function setApplicationEnabled(env: Env, slug: string, enabled: boolean): Promise<boolean> {
  const result = await env.DB.prepare(
    "UPDATE applications SET enabled = ?, updated_at = ? WHERE slug = ?",
  ).bind(enabled ? 1 : 0, new Date().toISOString(), slug).run();
  return result.meta.changes === 1;
}

export async function deleteApplication(env: Env, slug: string): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM applications WHERE slug = ?").bind(slug).run();
  return result.meta.changes === 1;
}

interface ApplicationRowRow {
  id: string;
  slug: string;
  name: string;
  description: string;
  protocol: ApplicationProtocol;
  binding: string | null;
  launchUrl: string | null;
  iconUrl: string | null;
  iconKey: string | null;
  categoryGroup: string | null;
  hideRaw: number;
  enabledRaw: number;
  createdBy: string;
  createdAt: string;
}

async function loadApplicationRow(env: Env, where: string, value: string): Promise<ApplicationRow | null> {
  const row = await env.DB.prepare(
    `SELECT id, slug, name, description, protocol, binding, launch_url AS launchUrl,
            icon_url AS iconUrl, icon_key AS iconKey, category_group AS categoryGroup,
            hide_from_dashboard AS hideRaw, enabled AS enabledRaw,
            created_by AS createdBy, created_at AS createdAt
     FROM applications WHERE ${where} LIMIT 1`,
  ).bind(value).first<ApplicationRowRow>();
  return row ? rowToApplicationRow(row) : null;
}

function rowToApplicationRow(row: ApplicationRowRow): ApplicationRow {
  return {
    ...row,
    hideFromDashboard: row.hideRaw === 1,
    enabled: row.enabledRaw === 1,
  };
}

/**
 * The user-visible launch list: enabled, not dashboard-hidden applications
 * whose "app:<slug>" access policy passes for the acting user (no policy row
 * = open to every signed-in user, authentik's empty-binding default).
 * Evaluation reads the STORED application policy (group bindings, account
 * gate) and follows the same engine rules as the issuance gates.
 */
export async function listVisibleApplications(env: Env, userId: string): Promise<ApplicationRow[]> {
  const candidates = (await listApplications(env)).filter((app) => app.enabled && !app.hideFromDashboard);
  const visible: ApplicationRow[] = [];
  for (const app of candidates) {
    const subject = `app:${app.slug}`;
    const stored = await loadAppAccessPolicy(env, subject).catch(() => null);
    const policy = stored ?? subjectPolicy(app.slug);
    const evaluation = await evaluateAppAccess(env, policy, userId);
    if (evaluation.allowed) visible.push(app);
  }
  return visible;
}

/** A synthetic in-memory policy for the app:<slug> subject gate. */
function subjectPolicy(slug: string): Parameters<typeof evaluateAppAccess>[1] {
  return {
    subject: `app:${slug}`,
    allowedMethods: "password,passkey",
    sessionTtlSeconds: null,
    bypassWindowSeconds: 0,
    enforcementMode: "enforce" as const,
    requireMfa: false,
    groups: [],
    requiredAccount: null,
  };
}
