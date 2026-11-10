/**
 * Custom object attributes: operator-defined properties attached to the
 * supported object types (Better Auth users, directory groups, accounts) and
 * stored as one flat JSON object per object in D1. See
 * docs/design/object-attributes.md.
 *
 * Values are constrained to JSON primitives (string, number, boolean, null)
 * so the store stays schemaless without admitting nested or opaque structures,
 * and the whole object is validated before any write reaches the database.
 */

import type { Env } from "../env";

export const OBJECT_ATTRIBUTE_TYPES = ["user", "group", "account"] as const;
export type ObjectAttributeType = (typeof OBJECT_ATTRIBUTE_TYPES)[number];

const KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const VALUE_STRING_LIMIT = 512;
// Control characters (except tab) are rejected in string values so audit
// storage and downstream protocols cannot be groomed with C0/C1 bytes.
const VALUE_CONTROL_PATTERN = /[\u0000-\u0008\u000b-\u001f\u007f]/;
const MAX_ATTRIBUTE_COUNT = 32;
const MAX_SERIALIZED_SIZE = 4096;

export type AttributeValue = string | number | boolean | null;
export type AttributeSet = Record<string, AttributeValue>;

export type ParsedAttributeSet =
  | { ok: true; attributes: AttributeSet }
  | { ok: false; error: string };

export function isObjectAttributeType(value: string): value is ObjectAttributeType {
  return (OBJECT_ATTRIBUTE_TYPES as readonly string[]).includes(value);
}

/**
 * Validate an `attributes` request value. Returns a canonical object (key
 * order preserved) or a precise error message the caller surfaces as 400.
 */
export function parseAttributesInput(input: unknown): ParsedAttributeSet {
  if (input === undefined) {
    return { ok: false, error: "attributes is required" };
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "attributes must be a JSON object" };
  }
  const entries = Object.entries(input as Record<string, unknown>);
  if (entries.length > MAX_ATTRIBUTE_COUNT) {
    return { ok: false, error: `attributes must contain at most ${MAX_ATTRIBUTE_COUNT} entries` };
  }
  const attributes: AttributeSet = {};
  for (const [key, value] of entries) {
    if (!KEY_PATTERN.test(key)) {
      return { ok: false, error: "attribute keys must be 1-64 characters from [A-Za-z0-9_.:-]" };
    }
    if (value === null) {
      attributes[key] = null;
      continue;
    }
    if (typeof value === "boolean") {
      attributes[key] = value;
      continue;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
        return { ok: false, error: "attribute numbers must be finite and within the safe integer range" };
      }
      attributes[key] = value;
      continue;
    }
    if (typeof value === "string") {
      if (value.length > VALUE_STRING_LIMIT) {
        return { ok: false, error: `attribute string values must be at most ${VALUE_STRING_LIMIT} characters` };
      }
      if (VALUE_CONTROL_PATTERN.test(value)) {
        return { ok: false, error: "attribute string values must not contain control characters" };
      }
      attributes[key] = value;
      continue;
    }
    return { ok: false, error: "attribute values must be strings, numbers, booleans or null" };
  }
  const serialized = JSON.stringify(attributes);
  if (serialized === null || new TextEncoder().encode(serialized).byteLength > MAX_SERIALIZED_SIZE) {
    return { ok: false, error: `attributes must serialize to at most ${MAX_SERIALIZED_SIZE} bytes` };
  }
  return { ok: true, attributes };
}

/** Does the referenced object exist in its owning table? */
export async function attributeObjectExists(
  env: Env,
  type: ObjectAttributeType,
  objectId: string,
): Promise<boolean> {
  const table = type === "user" ? '"user"' : type === "group" ? "directory_groups" : "accounts";
  const row = await env.DB.prepare(`SELECT id FROM ${table} WHERE id = ?`).bind(objectId).first();
  return row !== null;
}

export async function getObjectAttributes(
  env: Env,
  type: ObjectAttributeType,
  objectId: string,
): Promise<{ attributes: AttributeSet; updatedAt: string | null }> {
  const row = await env.DB.prepare(
    "SELECT attributes, updated_at AS updatedAt FROM object_attributes WHERE object_type = ? AND object_id = ?",
  ).bind(type, objectId).first<{ attributes: string; updatedAt: string }>();
  if (!row) return { attributes: {}, updatedAt: null };
  try {
    const parsed = JSON.parse(row.attributes) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return { attributes: parsed as AttributeSet, updatedAt: row.updatedAt };
    }
  } catch {
    // A corrupt row reads as empty; the write path below repairs it.
  }
  return { attributes: {}, updatedAt: null };
}

/**
 * Replace the attribute set for an object. An empty set removes the row, so
 * the store never keeps tombstones of cleared attributes.
 */
export async function setObjectAttributes(
  env: Env,
  type: ObjectAttributeType,
  objectId: string,
  attributes: AttributeSet,
  updatedBy: string | null,
): Promise<void> {
  if (Object.keys(attributes).length === 0) {
    await env.DB.prepare(
      "DELETE FROM object_attributes WHERE object_type = ? AND object_id = ?",
    ).bind(type, objectId).run();
    return;
  }
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO object_attributes (object_type, object_id, attributes, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (object_type, object_id) DO UPDATE SET
       attributes = excluded.attributes,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`,
  ).bind(type, objectId, JSON.stringify(attributes), updatedBy, now).run();
}

export async function deleteObjectAttributes(
  env: Env,
  type: ObjectAttributeType,
  objectId: string,
): Promise<boolean> {
  const removed = await env.DB.prepare(
    "DELETE FROM object_attributes WHERE object_type = ? AND object_id = ?",
  ).bind(type, objectId).run();
  return removed.meta.changes === 1;
}
