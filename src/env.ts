export interface Env extends Partial<WorkerBindings> {
  DB: D1Database;
  AUTH_SECRET: string;
  AUTH_BASE_URL: string;
  OIDC_EMAIL_DOMAIN?: string;
  /** "true" forces device-risk checks off whatever the stored setting says (lockout recovery). */
  FINGERPRINT_BREAK_GLASS?: string;
  FINGERPRINT_MODE?: "disabled" | "observe" | "enforce";
  FINGERPRINT_REGION?: "us" | "eu" | "ap";
  FINGERPRINT_SERVER_API_KEY?: string;
  /** Public (browser) key for the Fingerprint JS agent; safe to expose. */
  FINGERPRINT_PUBLIC_API_KEY?: string;
  FINGERPRINT_ALLOWED_ORIGINS?: string;
  FINGERPRINT_MIN_CONFIDENCE?: string;
  FINGERPRINT_SUSPECT_SCORE_THRESHOLD?: string;
  FINGERPRINT_MAX_EVENT_AGE_SECONDS?: string;
  /**
   * GeoIP login-history policy (authentik GeoIP Policy semantics; requires
   * FINGERPRINT_MODE != disabled and a position in event/history data).
   */
  GEOIP_CHECK_HISTORY_DISTANCE?: string;
  GEOIP_HISTORY_MAX_DISTANCE_KM?: string;
  GEOIP_DISTANCE_TOLERANCE_KM?: string;
  GEOIP_HISTORY_LOGIN_COUNT?: string;
  GEOIP_CHECK_IMPOSSIBLE_TRAVEL?: string;
  GEOIP_IMPOSSIBLE_TOLERANCE_KM?: string;
  /**
   * Session network/GeoIP binding (authentik hardening; request.cf data).
   * Violations end the session and write a logout-style audit event.
   */
  SESSION_BINDING_MODE?: "disabled" | "observe" | "enforce";
  SESSION_BINDING_NETWORK?: "off" | "asn" | "asn_and_ip";
  SESSION_BINDING_GEOIP?: "off" | "country" | "country_and_city";
  /** Step-up challenge window in seconds after a step_up risk decision (default 900). */
  STEP_UP_CHALLENGE_TTL_SECONDS?: string;
  ACTIVATION_TOKEN_TTL_MINUTES?: string;
  /** Organization name shown on the sign-in card and in the console (admin setting). */
  ORGANIZATION_NAME?: string;
  /** Second-factor policy (admin settings): requirement scope and which methods may be used. */
  MFA_REQUIRE?: string;
  MFA_ALLOW_TOTP?: string;
  MFA_ALLOW_OTP?: string;
  MFA_ALLOW_HOTP?: string;
  MFA_ALLOW_DUO?: string;
  /** "off" hides and refuses passkey sign-in everywhere. */
  LOGIN_ALLOW_PASSKEY?: string;
  /** Public Fingerprint endpoint (custom subdomain) the browser agent talks to. */
  FINGERPRINT_ENDPOINT?: string;
  ENABLE_ADMIN_BOOTSTRAP?: string;
  ADMIN_BOOTSTRAP_TOKEN?: string;
  ENABLE_MIGRATIONS?: string;
  MIGRATION_TOKEN?: string;
  ENABLE_DYNAMIC_CLIENT_REGISTRATION?: string;
  CLIENT_REGISTRATION_TOKEN?: string;
  ENABLE_TOKEN_EXCHANGE?: string;
  TOKEN_EXCHANGE_ALLOWED_RESOURCES?: string;
  /**
   * Release the session's active multi-account context (id, name, member
   * role) as namespaced claims on protocol tokens (OIDC access/ID token,
   * SAML assertion attributes, the JWT plugin's /token payload). Claims fail
   * closed when unset.
   */
  ENABLE_ACCOUNT_CLAIMS?: string;
  /**
   * Release custom object attributes of the acting user as claims on
   * protocol tokens (same surfaces as ENABLE_ACCOUNT_CLAIMS). Users'
   * group/account attributes stay unreleased pending a per-application
   * release policy.
   */
  ENABLE_ATTRIBUTE_CLAIMS?: string;
  /**
   * RFC 8707 protected-resource seed (JSON array of strings, or objects with
   * identifier/accessTokenTtl/allowedScopes). Seeded into the provider's
   * oauthResource table on first use; malformed config disables startup.
   */
  OAUTH_RESOURCES?: string;
  /** OAuth 1.0a server (RFC 5849 HMAC-SHA1 profile); routes fail closed. */
  ENABLE_OAUTH1?: string;
  /** RFC 8628 device authorization grant (docs/design/device-flow.md); routes and the token grant fail closed. */
  ENABLE_DEVICE_FLOW?: string;
  /** OpenID CIBA poll mode (docs/design/ciba.md); routes and the token grant fail closed. */
  ENABLE_CIBA?: string;
  /** Operator token for /api/oauth1/consumers management; >= 32 bytes when enabled. */
  OAUTH1_MANAGEMENT_TOKEN?: string;
  /** SSF (Shared Signals Framework) push receiver; routes fail closed. */
  ENABLE_SSF_RECEIVER?: string;
  /** SSF event sender (outbound SETs); routes fail closed. */
  ENABLE_SSF_SENDER?: string;
  /** Trusted SSF sender streams: JSON array of {id, issuer, audience, jwks, event_types}. */
  SSF_STREAMS?: string;
  /** Operator token for SSF management endpoints; >= 32 bytes when enabled. */
  SSF_MANAGEMENT_TOKEN?: string;
  SCIM_TARGET_ID?: string;
  SCIM_BASE_URL?: string;
  SCIM_BEARER_TOKEN?: string;
  ENABLE_SCIM_PROVISIONING?: string;
  ENABLE_INBOUND_SCIM?: string;
  INBOUND_SCIM_BEARER_TOKEN?: string;
  SCIM_DEV_LOOPBACK_TARGET?: string;
  SAML_IDP_ENTITY_ID?: string;
  SAML_IDP_SIGNING_CERTIFICATE?: string;
  SAML_IDP_SIGNING_PRIVATE_KEY?: string;
  SAML_IDP_PREVIOUS_SIGNING_CERTIFICATE?: string;
  SAML_IDP_PREVIOUS_SIGNING_PRIVATE_KEY?: string;
  MFA_OTP_EMAIL_WEBHOOK_URL?: string;
  MFA_SMS_WEBHOOK_URL?: string;
  /** SMS provider (twilio|solapi|webhook); with none selected, a legacy MFA_SMS_WEBHOOK_URL keeps working. */
  SMS_PROVIDER?: string;
  /** Sender number (or, for Twilio, a Messaging Service SID starting with MG). */
  SMS_FROM?: string;
  SMS_TWILIO_ACCOUNT_SID?: string;
  SMS_TWILIO_AUTH_TOKEN?: string;
  SMS_SOLAPI_API_KEY?: string;
  SMS_SOLAPI_API_SECRET?: string;
  /** Sent as a bearer token to the SMS webhook, when set. */
  SMS_WEBHOOK_TOKEN?: string;
  /** Sealed-storage AEAD key: 32 bytes, base64-encoded. */
  AEAD_SEALING_KEY?: string;
  /** Cipher for sealed storage; xchacha20poly1305 (default) or aes256gcm (FIPS-aligned). */
  SEALED_STORAGE_CIPHER?: string;
  /** OPAQUE (RFC 9807) server master key: 32 bytes, base64-encoded. */
  OPAQUE_MASTER_KEY?: string;
  /**
   * Emergency/operator escape hatch that re-enables the plaintext password
   * sign-in routes (/api/auth/sign-in/email, /api/auth/sign-in/username).
   * OPAQUE is the only credential login path; these routes fail CLOSED and
   * 404 unless this flag is explicitly "true". Keep it absent in production
   * vars; it exists solely for local smoke-test bootstrapping.
   */
  ALLOW_PLAINTEXT_PASSWORD_LOGIN?: string;
  RESEND_API_KEY?: string;
  MFA_OTP_EMAIL_FROM?: string;
  /**
   * Mail provider configuration (docs/design/email-providers.md). The active
   * provider is selected by MAIL_PROVIDER (smtp|resend|cloudflare|maileroo|
   * ses); when unset, a legacy deployment with RESEND_API_KEY keeps using
   * Resend. Sender identity: MAIL_FROM/MAIL_FROM_NAME are the generic
   * defaults, below the per-purpose overrides (INVITATION_EMAIL_FROM,
   * MFA_OTP_EMAIL_FROM).
   */
  MAIL_PROVIDER?: string;
  MAIL_FROM?: string;
  MAIL_FROM_NAME?: string;
  MAIL_REPLY_TO?: string;
  /** Resend: MAIL_RESEND_API_KEY supersedes the legacy RESEND_API_KEY spelling. */
  MAIL_RESEND_API_KEY?: string;
  /** Cloudflare Email Sending (REST API): account ID and an API token with Email Sending permission. */
  MAIL_CLOUDFLARE_ACCOUNT_ID?: string;
  MAIL_CLOUDFLARE_API_TOKEN?: string;
  /** Maileroo basic email API: a domain sending key. */
  MAIL_MAILEROO_API_KEY?: string;
  /** Standard AWS credential fallbacks for SES signing. */
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  /** Amazon SES v2: region + HMAC credentials (standard AWS_ACCESS_KEY_* fallbacks accepted). */
  MAIL_SES_REGION?: string;
  MAIL_SES_ACCESS_KEY_ID?: string;
  MAIL_SES_SECRET_ACCESS_KEY?: string;
  /** Custom SES endpoint (regional FIPS or a local mock); defaults to email.<region>.amazonaws.com. */
  MAIL_SES_ENDPOINT?: string;
  /** Generic SMTP relay: implicit TLS on 465, STARTTLS on 587 (per-port defaults). */
  MAIL_SMTP_HOST?: string;
  MAIL_SMTP_PORT?: string;
  /** "true" forces implicit TLS; "false" (with STARTTLS unset) opts into plaintext deliberately. */
  MAIL_SMTP_SECURE?: string;
  /** "true" forces the STARTTLS upgrade path regardless of port. */
  MAIL_SMTP_STARTTLS?: string;
  MAIL_SMTP_USERNAME?: string;
  MAIL_SMTP_PASSWORD?: string;
  DUO_IKEY?: string;
  DUO_SKEY?: string;
  DUO_API_HOSTNAME?: string;
  /** Reputation policies (docs/design/authentik-policies.md): ledger entry expiry. */
  REPUTATION_EXPIRY_HOURS?: string;
  /** Sender address for account invitation emails (falls back to MFA_OTP_EMAIL_FROM). */
  INVITATION_EMAIL_FROM?: string;
  /** Dev/mock webhook that records invitation emails instead of delivering them (headless local testing). */
  INVITATION_EMAIL_WEBHOOK_URL?: string;
  /** Built-in development mock mailbox at /dev/mocks/invitation-email; never enable in production. */
  ENABLE_DEV_MOCKS?: string;
  /** R2 bucket holding application icons (uploaded by administrators). */
  APPLICATION_ICONS?: R2Bucket;
  /** Access requests (docs/design/access-requests.md): best-effort reviewer notification webhook. */
  ACCESS_REQUEST_WEBHOOK_URL?: string;
  /**
   * Release the acting user's custom attributes to outbound SCIM targets as
   * the `urn:solixcorp:scim:1.0:CustomAttributes` extension on create/patch
   * payloads. Deliberate operator decision (privacy review per target);
   * fail-closed when unset.
   */
  ENABLE_SCIM_ATTRIBUTE_RELEASE?: string;
  /** Independent audit backup (docs/security/audit-backup.md): dated JSONL export target. */
  AUDIT_BACKUP?: R2Bucket;
}
