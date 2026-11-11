import type { Env } from "../env";

/**
 * Apply the initial Fingerprint retention windows. Raw provider IPs and event
 * payloads are never stored; event IDs are kept only for the replay window.
 */
export async function cleanupFingerprintData(env: Env, now = new Date()): Promise<void> {
  // Migrations can be incomplete. Clean every existing table rather than
  // skipping retention for all tables when one is absent.
  const existingTables = await env.DB.prepare(
    `SELECT name FROM sqlite_master
     WHERE type = 'table' AND name IN (
       'fingerprint_event_claims',
       'auth_device_observations',
       'fingerprint_risk_decisions',
       'trusted_devices',
       'fingerprint_lookup_limits',
       'app_grant_events',
       'login_history',
       'user_notifications'
     )`,
  ).all<{ name: string }>();
  const tables = new Set(existingTables.results.map((table) => table.name));

  const nowIso = now.toISOString();
  const observationsBefore = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const decisionsBefore = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString();
  const lookupsBefore = Math.floor(now.getTime() / 60_000) - 10;

  const statements: D1PreparedStatement[] = [];
  if (tables.has("fingerprint_event_claims")) {
    statements.push(env.DB.prepare("DELETE FROM fingerprint_event_claims WHERE expires_at < ?").bind(nowIso));
  }
  if (tables.has("auth_device_observations")) {
    statements.push(env.DB.prepare("DELETE FROM auth_device_observations WHERE occurred_at < ?").bind(observationsBefore));
  }
  if (tables.has("fingerprint_risk_decisions")) {
    statements.push(env.DB.prepare("DELETE FROM fingerprint_risk_decisions WHERE occurred_at < ?").bind(decisionsBefore));
  }
  if (tables.has("trusted_devices")) {
    statements.push(env.DB.prepare(
      `DELETE FROM trusted_devices
       WHERE (revoked_at IS NOT NULL AND revoked_at < ?)
          OR (revoked_at IS NULL AND expires_at < ?)`,
    ).bind(decisionsBefore, decisionsBefore));
  }
  // Grants are kept for the one-year audit window, with the verdict copied in.
  if (tables.has("app_grant_events")) {
    statements.push(env.DB.prepare("DELETE FROM app_grant_events WHERE occurred_at < ?")
      .bind(new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString()));
  }
  // Sign-in history for 180 days; read notifications for 90.
  if (tables.has("login_history")) {
    statements.push(env.DB.prepare("DELETE FROM login_history WHERE occurred_at < ?")
      .bind(new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000).toISOString()));
  }
  if (tables.has("user_notifications")) {
    statements.push(env.DB.prepare("DELETE FROM user_notifications WHERE read_at IS NOT NULL AND read_at < ?").bind(decisionsBefore));
  }
  if (tables.has("fingerprint_lookup_limits")) {
    statements.push(env.DB.prepare("DELETE FROM fingerprint_lookup_limits WHERE window_start < ?").bind(lookupsBefore));
  }
  if (statements.length > 0) await env.DB.batch(statements);
}
