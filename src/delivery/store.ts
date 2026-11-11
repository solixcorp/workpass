import { sealString, unsealString } from "../crypto/sealed";
import type { Env } from "../env";
import { envFor, type DeliveryKind } from "./catalog";

const CACHE_TTL_MS = 30_000;

export interface StoredDelivery {
  kind: DeliveryKind;
  provider: string;
  /** Everything that is not a secret. */
  values: Record<string, string>;
  /** Unsealed secrets; never leave the server. */
  secrets: Record<string, string>;
  updatedBy: string;
  updatedAt: string;
}

const cache = new WeakMap<object, { at: number; rows: Map<DeliveryKind, StoredDelivery> }>();

export function invalidateDelivery(env: Env): void {
  if (env.DB) cache.delete(env.DB);
}

const aad = (kind: DeliveryKind) => `delivery:${kind}`;

async function readAll(env: Env): Promise<Map<DeliveryKind, StoredDelivery>> {
  if (!env.DB) return new Map();
  const hit = cache.get(env.DB);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.rows;
  const rows = new Map<DeliveryKind, StoredDelivery>();
  try {
    const result = await env.DB.prepare("SELECT kind, provider, config, secrets, updated_by AS updatedBy, updated_at AS updatedAt FROM delivery_settings")
      .all<{ kind: DeliveryKind; provider: string; config: string; secrets: string; updatedBy: string; updatedAt: string }>();
    for (const row of result.results) {
      try {
        const secrets = row.secrets ? (JSON.parse(await unsealString(env, row.secrets, aad(row.kind))) as Record<string, string>) : {};
        rows.set(row.kind, { kind: row.kind, provider: row.provider, values: JSON.parse(row.config) as Record<string, string>, secrets, updatedBy: row.updatedBy, updatedAt: row.updatedAt });
      } catch {
        // A row that cannot be opened (the sealing key changed) is ignored: the deployment's own settings apply.
      }
    }
  } catch {
    // Not migrated yet.
  }
  cache.set(env.DB, { at: Date.now(), rows });
  return rows;
}

export async function loadDelivery(env: Env, kind: DeliveryKind, fresh = false): Promise<StoredDelivery | null> {
  if (fresh) invalidateDelivery(env);
  return (await readAll(env)).get(kind) ?? null;
}

/** The environment variables the stored configurations stand in for. */
export async function deliveryOverrides(env: Env): Promise<Record<string, string>> {
  const overrides: Record<string, string> = {};
  for (const stored of (await readAll(env)).values()) {
    Object.assign(overrides, envFor(stored.kind, stored.provider, { ...stored.values, ...stored.secrets }));
  }
  return overrides;
}

export async function saveDelivery(
  env: Env,
  input: { kind: DeliveryKind; provider: string; values: Record<string, string>; secrets: Record<string, string>; adminId: string },
): Promise<void> {
  const sealed = Object.keys(input.secrets).length ? await sealString(env, JSON.stringify(input.secrets), aad(input.kind)) : "";
  await env.DB.prepare(
    `INSERT INTO delivery_settings (kind, provider, config, secrets, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (kind) DO UPDATE SET provider = excluded.provider, config = excluded.config, secrets = excluded.secrets,
       updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
  ).bind(input.kind, input.provider, JSON.stringify(input.values), sealed, input.adminId, new Date().toISOString()).run();
  invalidateDelivery(env);
}

export async function removeDelivery(env: Env, kind: DeliveryKind): Promise<boolean> {
  const result = await env.DB.prepare("DELETE FROM delivery_settings WHERE kind = ?").bind(kind).run();
  invalidateDelivery(env);
  return (result.meta?.changes ?? 0) > 0;
}
