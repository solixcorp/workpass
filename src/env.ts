export interface Env {
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
  /** Cipher for sealed storage; defaults to xchacha20poly1305 (the only one). */
  SEALED_STORAGE_CIPHER?: string;
  RESEND_API_KEY?: string;
  MFA_OTP_EMAIL_FROM?: string;
  DUO_IKEY?: string;
  DUO_SKEY?: string;
  DUO_API_HOSTNAME?: string;
}
