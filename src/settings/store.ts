import type { Env } from "../env";
import { deliveryOverrides } from "../delivery/store";
import { SETTINGS, settingDefinition, type SettingDefinition } from "./registry";

const CACHE_TTL_MS = 30_000;

interface StoredSetting {
  value: string;
  updatedBy: string;
  updatedAt: string;
}

interface CacheEntry {
  at: number;
  rows: Map<string, StoredSetting>;
}

// Keyed by the D1 binding so isolates and tests never share stored values.
const cache = new WeakMap<object, CacheEntry>();

async function readRows(env: Env): Promise<Map<string, StoredSetting>> {
  // No database (misconfigured deployment, unit tests): environment values apply.
  if (!env.DB) return new Map();
  const hit = cache.get(env.DB);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.rows;
  const rows = new Map<string, StoredSetting>();
  try {
    const result = await env.DB.prepare(
      "SELECT key, value, updated_by AS updatedBy, updated_at AS updatedAt FROM app_settings",
    ).all<{ key: string; value: string; updatedBy: string; updatedAt: string }>();
    // Only an explicitly reported failure is an outage; result shapes that omit
    // `success` (minimal test doubles) still count as successful reads.
    if ((result as { success?: unknown }).success === false) throw new Error("Settings read failed");
    if (!Array.isArray(result.results)) throw new Error("Settings read returned an invalid shape");
    for (const row of result.results) {
      if (settingDefinition(row.key)) rows.set(row.key, row);
    }
  } catch (error) {
    // Keep administrator policy during an outage; retry after the usual TTL.
    if (hit) {
      cache.set(env.DB, { at: Date.now(), rows: hit.rows });
      return hit.rows;
    }
    // Only an explicit missing-table error permits first-run migrations. Do not
    // cache this startup fallback; a migrated, empty table is a successful read.
    if (error instanceof Error && /^(?:D1_ERROR: )?no such table: (?:main\.)?app_settings(?:: SQLITE_ERROR)?$/.test(error.message)) {
      return rows;
    }
    throw error;
  }
  cache.set(env.DB, { at: Date.now(), rows });
  return rows;
}

export function invalidateSettings(env: Env): void {
  const hit = env.DB && cache.get(env.DB);
  // Force a refresh without discarding the last-known-good outage fallback.
  if (hit) hit.at = Number.NEGATIVE_INFINITY;
}

/**
 * The environment with stored settings laid over it. Everything downstream
 * keeps reading `env.MFA_REQUIRE` and friends; a stored value simply
 * takes the place of the deployment value for this request.
 */
export async function applySettings(env: Env): Promise<Env> {
  const rows = await readRows(env);
  const overrides: Record<string, string> = {};
  for (const [key, row] of rows) {
    const definition = settingDefinition(key);
    if (definition) overrides[definition.envName] = row.value;
  }
  // How e-mail and SMS leave the system, when an administrator chose.
  Object.assign(overrides, await deliveryOverrides(env));
  if (Object.keys(overrides).length === 0) return env;
  return { ...env, ...overrides } as Env;
}

export type SettingSource = "admin" | "env" | "default";

export interface ResolvedSetting {
  definition: SettingDefinition;
  value: string;
  source: SettingSource;
  updatedBy: string | null;
  updatedAt: string | null;
}

export async function resolveSettings(env: Env): Promise<ResolvedSetting[]> {
  invalidateSettings(env);
  const rows = await readRows(env);
  return SETTINGS.map((definition) => {
    const stored = rows.get(definition.key);
    if (stored) {
      return { definition, value: stored.value, source: "admin", updatedBy: stored.updatedBy, updatedAt: stored.updatedAt };
    }
    const fromEnv = (env as unknown as Record<string, unknown>)[definition.envName];
    if (typeof fromEnv === "string" && fromEnv.trim() !== "") {
      return { definition, value: fromEnv.trim(), source: "env", updatedBy: null, updatedAt: null };
    }
    return { definition, value: definition.default, source: "default", updatedBy: null, updatedAt: null };
  });
}

export async function saveSetting(env: Env, key: string, value: string, actorUserId: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO app_settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
  ).bind(key, value, actorUserId, new Date().toISOString()).run();
  invalidateSettings(env);
}

export async function clearSetting(env: Env, key: string): Promise<void> {
  await env.DB.prepare("DELETE FROM app_settings WHERE key = ?").bind(key).run();
  invalidateSettings(env);
}
