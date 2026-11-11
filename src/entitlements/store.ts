import type { Env } from "../env";
import { evaluateAppAccess, loadAppAccessPolicy } from "../access/policies";

type App = { id: string; slug: string; enabled: number };

export async function canOpen(env: Env, app: App, userId: string): Promise<boolean> {
  if (!app.enabled) return false;
  const subject = `app:${app.slug}`;
  const policy = await loadAppAccessPolicy(env, subject) ?? {
    subject, allowedMethods: "password,passkey", sessionTtlSeconds: null,
    bypassWindowSeconds: 0, enforcementMode: "enforce" as const,
    requireMfa: false, groups: [], requiredAccount: null,
  };
  return (await evaluateAppAccess(env, policy, userId)).allowed;
}

export async function effectiveEntitlements(env: Env, app: App, userId: string): Promise<string[]> {
  if (!(await canOpen(env, app, userId))) return [];
  const result = await env.DB.prepare(`SELECT DISTINCT e.key FROM app_entitlements e
    JOIN app_entitlement_groups eg ON eg.entitlement_id = e.id
    JOIN directory_group_members m ON m.group_id = eg.group_id
    WHERE e.application_id = ? AND m.user_id = ? ORDER BY e.key`).bind(app.id, userId).all<{ key: string }>();
  return result.results.map((row) => row.key);
}

export async function entitlementsForSubject(env: Env, subject: string, userId: string): Promise<string[] | null> {
  const colon = subject.indexOf(":");
  const protocol = subject.slice(0, colon);
  if (colon < 0 || !["oidc", "saml", "wsfed"].includes(protocol)) return null;
  const apps = await env.DB.prepare("SELECT id, slug, enabled FROM applications WHERE protocol = ? AND binding = ? LIMIT 2")
    .bind(protocol, subject.slice(colon + 1)).all<App>();
  if (apps.results.length !== 1) return null;
  const app = apps.results[0]!;
  const exists = await env.DB.prepare("SELECT 1 FROM app_entitlements WHERE application_id = ? LIMIT 1").bind(app.id).first();
  if (!exists) return null;
  return effectiveEntitlements(env, app, userId);
}

export async function listEntitlements(env: Env, app: App) {
  const result = await env.DB.prepare("SELECT id, key, name, description FROM app_entitlements WHERE application_id = ? ORDER BY key")
    .bind(app.id).all<{ id: string; key: string; name: string; description: string }>();
  const entitlements = [];
  for (const entitlement of result.results) {
    const groups = await env.DB.prepare(`SELECT g.id, g.name FROM directory_groups g JOIN app_entitlement_groups eg
      ON eg.group_id = g.id WHERE eg.entitlement_id = ? ORDER BY g.name, g.id`).bind(entitlement.id).all<{ id: string; name: string }>();
    const members = await env.DB.prepare(`SELECT DISTINCT m.user_id AS id FROM directory_group_members m
      JOIN app_entitlement_groups eg ON eg.group_id = m.group_id WHERE eg.entitlement_id = ?`)
      .bind(entitlement.id).all<{ id: string }>();
    let memberCount = 0;
    for (const member of members.results) if (await canOpen(env, app, member.id)) memberCount++;
    entitlements.push({ ...entitlement, groups: groups.results, memberCount });
  }
  return entitlements;
}
