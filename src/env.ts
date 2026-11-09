export interface Env extends Partial<WorkerBindings> {
  DB: D1Database;
  AUTH_SECRET: string;
  AUTH_BASE_URL: string;
  OIDC_EMAIL_DOMAIN?: string;
  FINGERPRINT_MODE?: "disabled" | "observe" | "enforce";
  FINGERPRINT_REGION?: "us" | "eu" | "ap";
  FINGERPRINT_SERVER_API_KEY?: string;
  FINGERPRINT_ALLOWED_ORIGINS?: string;
  FINGERPRINT_MIN_CONFIDENCE?: string;
  FINGERPRINT_SUSPECT_SCORE_THRESHOLD?: string;
  FINGERPRINT_MAX_EVENT_AGE_SECONDS?: string;
  ENABLE_ADMIN_BOOTSTRAP?: string;
  ADMIN_BOOTSTRAP_TOKEN?: string;
  ENABLE_MIGRATIONS?: string;
  MIGRATION_TOKEN?: string;
  ENABLE_DYNAMIC_CLIENT_REGISTRATION?: string;
  CLIENT_REGISTRATION_TOKEN?: string;
  ENABLE_TOKEN_EXCHANGE?: string;
  TOKEN_EXCHANGE_ALLOWED_RESOURCES?: string;
  /**
   * RFC 8707 protected-resource seed (JSON array of strings, or objects with
   * identifier/accessTokenTtl/allowedScopes). Seeded into the provider's
   * oauthResource table on first use; malformed config disables startup.
   */
  OAUTH_RESOURCES?: string;
  /** OAuth 1.0a server (RFC 5849 HMAC-SHA1 profile); routes fail closed. */
  ENABLE_OAUTH1?: string;
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
  /** Sealed-storage AEAD key: 32 bytes, base64-encoded. */
  AEAD_SEALING_KEY?: string;
  /** Cipher for sealed storage; xchacha20poly1305 (default) or aes256gcm (FIPS-aligned). */
  SEALED_STORAGE_CIPHER?: string;
  /** OPAQUE (RFC 9807) server master key: 32 bytes, base64-encoded. */
  OPAQUE_MASTER_KEY?: string;
  RESEND_API_KEY?: string;
  MFA_OTP_EMAIL_FROM?: string;
  DUO_IKEY?: string;
  DUO_SKEY?: string;
  DUO_API_HOSTNAME?: string;
}
