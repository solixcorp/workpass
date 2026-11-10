import type { Env } from "../env";

export async function ensureApplicationTables(env: Env): Promise<void> {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS opaque_server_material (
      id TEXT PRIMARY KEY NOT NULL,
      material TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS opaque_credential_records (
      user_id TEXT PRIMARY KEY NOT NULL,
      record TEXT NOT NULL,
      credential_identifier TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS opaque_login_transcripts (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT,
      client_identity TEXT,
      expected TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    )`,
  ).run();
  // Fingerprint event ids travel through the two-phase login on the
  // transcript row (added in place for existing databases).
  try {
    await env.DB.prepare("ALTER TABLE opaque_login_transcripts ADD COLUMN fingerprint_event_id TEXT").run();
  } catch {
    // Column already present.
  }
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS opaque_transcript_expiry_idx ON opaque_login_transcripts (expires_at)",
  ).run();
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
  // Travel-plausibility coordinates: server-resolved points only (event
  // geolocation or a country centroid); never raw IP addresses.
  if (!observationColumns.results.some((column) => column.name === "latitude")) {
    await env.DB.prepare("ALTER TABLE auth_device_observations ADD COLUMN latitude REAL").run();
  }
  if (!observationColumns.results.some((column) => column.name === "longitude")) {
    await env.DB.prepare("ALTER TABLE auth_device_observations ADD COLUMN longitude REAL").run();
  }
  if (!observationColumns.results.some((column) => column.name === "geo_source")) {
    await env.DB.prepare("ALTER TABLE auth_device_observations ADD COLUMN geo_source TEXT").run();
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
    `CREATE TABLE IF NOT EXISTS mfa_hotp_tokens (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      label TEXT NOT NULL,
      secret_base32 TEXT NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS mfa_hotp_tokens_user_idx ON mfa_hotp_tokens (user_id)",
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
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS session_mfa_proofs (
      session_token TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      verified_at TEXT NOT NULL
    )`,
  ).run();
  // Multi-account switching: tenant-like accounts a user may belong to and
  // switch between (see docs/design/multi-accounts.md).
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL DEFAULT '',
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS account_members (
      account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
      granted_by TEXT NOT NULL,
      granted_at TEXT NOT NULL,
      PRIMARY KEY (account_id, user_id)
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS account_members_user_idx ON account_members (user_id)",
  ).run();
  // The active account is bound per session token, mirroring the
  // session_mfa_proofs pattern, so two sessions of the same user may hold
  // different account contexts and no Better Auth schema change is needed.
  // A secondary session_id column lets protocol claim release (OIDC `sid`)
  // resolve the account without holding raw session tokens in token
  // issuance paths.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS account_session_contexts (
      session_token TEXT PRIMARY KEY NOT NULL,
      session_id TEXT,
      user_id TEXT NOT NULL,
      account_id TEXT NOT NULL,
      switched_at TEXT NOT NULL
    )`,
  ).run();
  const contextColumns = await env.DB.prepare("PRAGMA table_info(account_session_contexts)")
    .all<{ name: string }>();
  if (!contextColumns.results.some((column) => column.name === "session_id")) {
    await env.DB.prepare("ALTER TABLE account_session_contexts ADD COLUMN session_id TEXT").run();
  }
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS account_session_contexts_time_idx ON account_session_contexts (switched_at)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS account_session_contexts_session_idx ON account_session_contexts (session_id)",
  ).run();
  // Per-account authorization dimension: an access policy may additionally
  // require the user to hold membership in one account (null = no account
  // gate, the platform-wide default). Column added in place.
  try {
    await env.DB.prepare("ALTER TABLE app_access_policies ADD COLUMN required_account TEXT").run();
  } catch {
    // Column already present.
  }
  // Per-application claim release policy: when a row exists for a subject it
  // gates which released claim kinds reach that application (an AND with the
  // global operator flags; no row keeps flag-only behavior).
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS claim_release_policies (
      subject TEXT PRIMARY KEY NOT NULL,
      allow_account_claims INTEGER NOT NULL DEFAULT 1 CHECK (allow_account_claims IN (0, 1)),
      allow_user_attributes INTEGER NOT NULL DEFAULT 1 CHECK (allow_user_attributes IN (0, 1)),
      updated_by TEXT,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  // Per-application claim release policy: when a row exists for a subject it
  // gates which released claim kinds reach that application (an AND with the
  // global operator flags; no row keeps flag-only behavior). The optional
  // attribute allowlist narrows the released user-attribute keys further
  // (in-place column).
  try {
    await env.DB.prepare("ALTER TABLE claim_release_policies ADD COLUMN attribute_allowlist TEXT").run();
  } catch {
    // Column already present.
  }
  // Group/account attributes release: per-application columns added in place
  // (an AND with the operator flags, like the other release kinds).
  try {
    await env.DB.prepare("ALTER TABLE claim_release_policies ADD COLUMN allow_account_attributes INTEGER").run();
  } catch {
    // Column already present.
  }
  try {
    await env.DB.prepare("ALTER TABLE claim_release_policies ADD COLUMN allow_group_attributes INTEGER").run();
  } catch {
    // Column already present.
  }
  // Applications: the authentik-style unified registry over every backed
  // protocol (saml, wsfed, oidc, swa) plus plain bookmark apps (no binding,
  // launch URL only). Visibility follows the app:<slug> access-policy
  // subject; nothing configured means every signed-in user sees the app.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS applications (
      id TEXT PRIMARY KEY NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      protocol TEXT NOT NULL CHECK (protocol IN ('bookmark', 'saml', 'wsfed', 'oidc', 'swa')),
      binding TEXT,
      launch_url TEXT,
      icon_url TEXT,
      icon_key TEXT,
      category_group TEXT,
      hide_from_dashboard INTEGER NOT NULL DEFAULT 0 CHECK (hide_from_dashboard IN (0, 1)),
      enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  // The uploaded-icon key column was added after the registry shipped:
  // in-place ALTER for deployed databases.
  try {
    await env.DB.prepare("ALTER TABLE applications ADD COLUMN icon_key").run();
  } catch {
    // Column already present.
  }
  // Account invitations: opaque single-use join tokens created by the admin
  // surface and redeemed by a signed-in user (see docs/design/multi-accounts.md).
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS account_invitations (
      token TEXT PRIMARY KEY NOT NULL,
      account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS account_invitations_expiry_idx ON account_invitations (expires_at)",
  ).run();
  // Account invitations: explicit operator-decided email delivery, tracked on
  // the row (in-place columns for deployed databases).
  try {
    await env.DB.prepare("ALTER TABLE account_invitations ADD COLUMN deliver_to TEXT").run();
  } catch {
    // Column already present.
  }
  try {
    await env.DB.prepare("ALTER TABLE account_invitations ADD COLUMN delivered_at TEXT").run();
  } catch {
    // Column already present.
  }
  // Custom object attributes: one flat JSON object per (object_type, object_id)
  // (see docs/design/object-attributes.md).
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS object_attributes (
      object_type TEXT NOT NULL CHECK (object_type IN ('user', 'group', 'account')),
      object_id TEXT NOT NULL,
      attributes TEXT NOT NULL,
      updated_by TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (object_type, object_id)
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS session_mfa_proofs_time_idx ON session_mfa_proofs (verified_at)",
  ).run();
  // Account Lockdown (docs/security/account-lockdown.md): one row per lockdown
  // action, including the recorded reason; a lifted row keeps history.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS account_lockdowns (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      actor_user_id TEXT NOT NULL,
      source TEXT NOT NULL CHECK (source IN ('admin', 'self_service')),
      reason TEXT NOT NULL,
      created_at TEXT NOT NULL,
      lifted_at TEXT,
      lifted_by TEXT
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS account_lockdowns_user_idx ON account_lockdowns (user_id, created_at)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS account_lockdowns_active_idx ON account_lockdowns (user_id) WHERE lifted_at IS NULL",
  ).run();
  // Session network/GeoIP binding envelopes (docs/security/session-geo-binding.md):
  // keyed digests plus country code; the raw IP and city string are never stored.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS session_network_bindings (
      session_token TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      network_digest TEXT,
      asn_digest TEXT,
      country_code TEXT,
      city_digest TEXT,
      network_level TEXT NOT NULL CHECK (network_level IN ('off', 'asn', 'asn_and_ip')),
      geoip_level TEXT NOT NULL CHECK (geoip_level IN ('off', 'country', 'country_and_city')),
      bound_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS session_network_bindings_user_idx ON session_network_bindings (user_id)",
  ).run();
  // Step-up challenge requirements (docs/security/device-risk-and-trust.md):
  // sessions flagged by a risky decision must complete a second factor before
  // SSO issuance; a recorded proof satisfies the user's open challenges.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS session_step_up_requirements (
      session_token TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      reasons TEXT NOT NULL,
      request_path TEXT NOT NULL,
      created_at TEXT NOT NULL,
      challenge_expires_at TEXT NOT NULL,
      satisfied_at TEXT,
      satisfied_method TEXT
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS session_step_up_requirements_user_idx ON session_step_up_requirements (user_id, challenge_expires_at)",
  ).run();
  // Access requests (docs/design/access-requests.md): just-in-time application
  // access with reviewer approval and time-limited temporal grants.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS request_rules (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL UNIQUE,
      min_reviewers INTEGER NOT NULL DEFAULT 1 CHECK (min_reviewers BETWEEN 1 AND 5),
      notify_mode TEXT NOT NULL DEFAULT 'all' CHECK (notify_mode IN ('all', 'random')),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS request_rule_reviewers (
      rule_id TEXT NOT NULL REFERENCES request_rules (id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      PRIMARY KEY (rule_id, user_id)
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS request_rule_reviewer_groups (
      rule_id TEXT NOT NULL REFERENCES request_rules (id) ON DELETE CASCADE,
      group_id TEXT NOT NULL REFERENCES directory_groups (id) ON DELETE CASCADE,
      PRIMARY KEY (rule_id, group_id)
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS request_rule_bindings (
      id TEXT PRIMARY KEY NOT NULL,
      subject TEXT NOT NULL UNIQUE,
      rule_id TEXT NOT NULL REFERENCES request_rules (id) ON DELETE CASCADE,
      pending_expiry_seconds INTEGER NOT NULL CHECK (pending_expiry_seconds BETWEEN 60 AND 7776000),
      max_granted_expiry_seconds INTEGER NOT NULL CHECK (max_granted_expiry_seconds BETWEEN 3600 AND 2592000),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS request_binding_requesters (
      binding_id TEXT NOT NULL REFERENCES request_rule_bindings (id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      PRIMARY KEY (binding_id, user_id)
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS request_binding_requester_groups (
      binding_id TEXT NOT NULL REFERENCES request_rule_bindings (id) ON DELETE CASCADE,
      group_id TEXT NOT NULL REFERENCES directory_groups (id) ON DELETE CASCADE,
      PRIMARY KEY (binding_id, group_id)
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS access_requests (
      id TEXT PRIMARY KEY NOT NULL,
      subject TEXT NOT NULL,
      user_id TEXT NOT NULL,
      binding_id TEXT NOT NULL REFERENCES request_rule_bindings (id) ON DELETE CASCADE,
      justification TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'lapsed', 'revoked')),
      requested_expiry_seconds INTEGER NOT NULL,
      granted_expires_at TEXT,
      pending_expires_at TEXT NOT NULL,
      decided_at TEXT,
      decided_by TEXT,
      decision_note TEXT,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS access_requests_subject_idx ON access_requests (subject, status)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS access_requests_user_idx ON access_requests (user_id, created_at)",
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS access_requests_pending_idx ON access_requests (status, pending_expires_at) WHERE status = 'pending'",
  ).run();
  // One pending request per user and subject, enforced by the database itself.
  await env.DB.prepare(
    `CREATE UNIQUE INDEX IF NOT EXISTS access_requests_one_pending_idx
      ON access_requests (user_id, subject) WHERE status = 'pending'`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS access_request_approvals (
      request_id TEXT NOT NULL REFERENCES access_requests (id) ON DELETE CASCADE,
      reviewer_id TEXT NOT NULL,
      decision TEXT NOT NULL CHECK (decision IN ('approved', 'denied')),
      note TEXT,
      decided_at TEXT NOT NULL,
      PRIMARY KEY (request_id, reviewer_id)
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS app_temporal_grants (
      request_id TEXT PRIMARY KEY NOT NULL REFERENCES access_requests (id) ON DELETE CASCADE,
      subject TEXT NOT NULL,
      user_id TEXT NOT NULL,
      granted_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      approved_by TEXT NOT NULL,
      revoked_at TEXT
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS app_temporal_grants_user_idx ON app_temporal_grants (user_id, subject)",
  ).run();
  // Independent audit backup watermark (docs/security/audit-backup.md): the
  // contiguous log position already exported to the R2 object store.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS audit_backup_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      log_pos INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    )`,
  ).run();
  // Admin-issued one-time account recovery tokens (docs/security/account-lockdown.md):
  // only the HMAC digest of the token is stored; redemption resets the password
  // and lifts the active lockdown in one statement batch.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS account_recovery_tokens (
      id TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      token_digest TEXT NOT NULL UNIQUE,
      lockdown_id TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS account_recovery_tokens_expiry_idx ON account_recovery_tokens (expires_at)",
  ).run();
  // Authentik-benchmarked policy framework (docs/design/authentik-policies.md).
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL CHECK (type IN ('expression', 'password', 'password_expiry', 'password_uniqueness', 'reputation', 'geoip', 'event_matcher')),
      config TEXT NOT NULL DEFAULT '{}',
      enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
      execution_logging INTEGER NOT NULL DEFAULT 0 CHECK (execution_logging IN (0, 1)),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS policy_bindings (
      id TEXT PRIMARY KEY NOT NULL,
      target TEXT NOT NULL CHECK (target IN ('application', 'login', 'password_entry', 'user_write', 'notification_rule')),
      target_ref TEXT NOT NULL,
      policy_id TEXT REFERENCES policies (id) ON DELETE CASCADE,
      bind_user_id TEXT,
      bind_group_id TEXT REFERENCES directory_groups (id) ON DELETE CASCADE,
      order_index INTEGER NOT NULL DEFAULT 0,
      mode TEXT NOT NULL DEFAULT 'all' CHECK (mode IN ('all', 'any')),
      negate INTEGER NOT NULL DEFAULT 0 CHECK (negate IN (0, 1)),
      failure_result TEXT NOT NULL DEFAULT 'fail' CHECK (failure_result IN ('fail', 'pass')),
      enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      CHECK (
        (CASE WHEN policy_id IS NULL THEN 0 ELSE 1 END)
        + (CASE WHEN bind_user_id IS NULL THEN 0 ELSE 1 END)
        + (CASE WHEN bind_group_id IS NULL THEN 0 ELSE 1 END) = 1
      )
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS policy_bindings_target_idx ON policy_bindings (target, target_ref, order_index)",
  ).run();
  // Password policy family (docs/design/authentik-policies.md).
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS password_meta (
      user_id TEXT PRIMARY KEY NOT NULL,
      changed_at TEXT NOT NULL,
      unusable INTEGER NOT NULL DEFAULT 0 CHECK (unusable IN (0, 1))
    )`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS password_history (
      user_id TEXT NOT NULL,
      salt TEXT NOT NULL,
      digest TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS password_history_user_idx ON password_history (user_id, created_at)",
  ).run();
  // Reputation ledger (authentik reputation policies): login outcomes move the
  // score of a client IP or username toward or away from the threshold.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS reputation_scores (
      kind TEXT NOT NULL CHECK (kind IN ('ip', 'username')),
      identifier TEXT NOT NULL,
      score INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (kind, identifier)
    )`,
  ).run();
}
