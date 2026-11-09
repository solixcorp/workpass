import type { Env } from "../env";

export async function ensureApplicationTables(env: Env): Promise<void> {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY NOT NULL,
      occurred_at TEXT NOT NULL,
      actor_user_id TEXT,
      target_user_id TEXT,
      event_type TEXT NOT NULL,
      outcome TEXT NOT NULL,
      request_path TEXT NOT NULL,
      log_pos INTEGER,
      content_hash TEXT
    )`,
  ).run();
  // Databases created before tamper-evidence columns existed are altered in
  // place; a missing column raises and is retried by re-running migration.
  try {
    await env.DB.prepare("ALTER TABLE audit_events ADD COLUMN log_pos INTEGER").run();
  } catch {
    // Column already present.
  }
  try {
    await env.DB.prepare("ALTER TABLE audit_events ADD COLUMN content_hash TEXT").run();
  } catch {
    // Column already present.
  }
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS audit_events_log_pos_idx ON audit_events (log_pos)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx ON audit_events (occurred_at)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS audit_events_order_idx ON audit_events (occurred_at DESC, id DESC)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON audit_events (actor_user_id, occurred_at)",
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS bootstrap_state (
      slot INTEGER PRIMARY KEY CHECK (slot = 1),
      claimed_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS fingerprint_event_claims (
      event_id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT,
      context TEXT NOT NULL,
      claimed_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT,
      claim_token TEXT
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS fingerprint_event_claims_expires_idx ON fingerprint_event_claims (expires_at)",
  ).run();
  const claimColumns = await env.DB.prepare("PRAGMA table_info(fingerprint_event_claims)")
    .all<{ name: string }>();
  if (!claimColumns.results.some((column) => column.name === "claim_token")) {
    await env.DB.prepare("ALTER TABLE fingerprint_event_claims ADD COLUMN claim_token TEXT").run();
  }
  if (!claimColumns.results.some((column) => column.name === "consumed_at")) {
    await env.DB.prepare("ALTER TABLE fingerprint_event_claims ADD COLUMN consumed_at TEXT").run();
  }
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS trusted_devices (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      visitor_digest TEXT NOT NULL,
      label TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      UNIQUE (user_id, visitor_digest)
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS trusted_devices_user_active_idx ON trusted_devices (user_id, revoked_at, expires_at)",
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS auth_device_observations (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      visitor_digest TEXT NOT NULL,
      network_digest TEXT,
      country_code TEXT,
      occurred_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS auth_device_observations_user_time_idx ON auth_device_observations (user_id, occurred_at)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS auth_device_observations_time_idx ON auth_device_observations (occurred_at)",
  ).run();
  const observationColumns = await env.DB.prepare("PRAGMA table_info(auth_device_observations)")
    .all<{ name: string }>();
  if (!observationColumns.results.some((column) => column.name === "network_digest")) {
    await env.DB.prepare("ALTER TABLE auth_device_observations ADD COLUMN network_digest TEXT").run();
  }
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS fingerprint_risk_decisions (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT,
      event_id TEXT,
      action TEXT NOT NULL,
      reasons TEXT NOT NULL,
      request_path TEXT NOT NULL,
      occurred_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS fingerprint_risk_decisions_time_idx ON fingerprint_risk_decisions (occurred_at)",
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS fingerprint_lookup_limits (
      budget_key TEXT PRIMARY KEY NOT NULL,
      window_start INTEGER NOT NULL,
      request_count INTEGER NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS scim_user_mappings (
      target_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      external_user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (target_id, user_id),
      UNIQUE (target_id, external_user_id)
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS scim_operations (
      id TEXT PRIMARY KEY NOT NULL,
      target_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      operation TEXT NOT NULL CHECK (operation IN ('create', 'update', 'deactivate')),
      status TEXT NOT NULL CHECK (status IN ('pending', 'in_progress', 'succeeded', 'failed', 'outcome_unknown')),
      remote_status INTEGER,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE UNIQUE INDEX IF NOT EXISTS scim_operations_active_idx
     ON scim_operations (target_id, user_id)
     WHERE status IN ('pending', 'in_progress', 'outcome_unknown')`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS directory_groups (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL DEFAULT '',
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS directory_group_members (
      group_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      granted_by TEXT NOT NULL,
      granted_at TEXT NOT NULL,
      PRIMARY KEY (group_id, user_id)
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS directory_group_members_user_idx ON directory_group_members (user_id)",
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS swa_applications (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      origin TEXT NOT NULL UNIQUE,
      enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS swa_grants (
      nonce TEXT PRIMARY KEY NOT NULL,
      application_id TEXT NOT NULL REFERENCES swa_applications (id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS swa_grants_application_idx ON swa_grants (application_id)",
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS app_access_policies (
      subject TEXT PRIMARY KEY NOT NULL,
      allowed_methods TEXT NOT NULL DEFAULT 'password,passkey',
      session_ttl_seconds INTEGER,
      bypass_window_seconds INTEGER NOT NULL DEFAULT 28800,
      enforcement_mode TEXT NOT NULL DEFAULT 'enforce' CHECK (enforcement_mode IN ('enforce', 'observe')),
      require_mfa INTEGER NOT NULL DEFAULT 0 CHECK (require_mfa IN (0, 1)),
      updated_by TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS app_policy_groups (
      subject TEXT NOT NULL,
      group_id TEXT NOT NULL REFERENCES directory_groups (id) ON DELETE CASCADE,
      PRIMARY KEY (subject, group_id)
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS app_issuance_history (
      subject TEXT NOT NULL,
      user_id TEXT NOT NULL,
      issued_at TEXT NOT NULL,
      enforcement_mode TEXT NOT NULL,
      method TEXT,
      PRIMARY KEY (subject, user_id, issued_at)
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS app_issuance_history_user_idx ON app_issuance_history (user_id, issued_at)",
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS wsfed_relying_parties (
      id TEXT PRIMARY KEY NOT NULL,
      realm TEXT NOT NULL UNIQUE,
      reply_url TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS saml_service_providers (
      id TEXT PRIMARY KEY NOT NULL,
      entity_id TEXT NOT NULL UNIQUE,
      acs_url TEXT NOT NULL,
      signing_certificate TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1))
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS saml_request_claims (
      provider_id TEXT NOT NULL,
      request_id TEXT NOT NULL,
      claimed_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      PRIMARY KEY (provider_id, request_id)
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS saml_request_claims_expiry_idx ON saml_request_claims (expires_at)",
  ).run();
}
