/**
 * Provider model for transactional email delivery. A deployment selects one
 * provider (SMTP, Resend, Cloudflare Email Sending, Maileroo, Amazon SES v2)
 * through environment configuration; the registry resolves it and the caller
 * dispatches messages behind a single interface. Nothing here talks about
 * purposes (invitation/OTP) — callers resolve their own sender identity and
 * dev/webhook override paths live in `send.ts` above this layer.
 *
 * Selection (fail-closed): `MAIL_PROVIDER` names the provider explicitly.
 * When it is unset, a deployment with a Resend key keeps working through the
 * legacy Resend path (the only provider before selection existed). An unknown
 * value throws instead of silently sending through nothing.
 */

import type { Env } from "../env";
import { cloudflareProvider } from "./providers/cloudflare";
import { mailerooProvider } from "./providers/maileroo";
import { resendProvider } from "./providers/resend";
import { sesProvider } from "./providers/ses";
import { smtpProvider } from "./providers/smtp";

export const MAIL_PROVIDER_IDS = ["smtp", "resend", "cloudflare", "maileroo", "ses"] as const;

export type MailProviderId = (typeof MAIL_PROVIDER_IDS)[number];

export interface MailMessage {
  /** Recipient address. Every current call path delivers to one recipient. */
  to: string;
  subject: string;
  text: string;
  /** Optional HTML alternative body (no call site uses it yet). */
  html?: string;
  /** Sender mailbox (envelope and header). Required; delivery fails closed. */
  from: string;
  /** Optional display name for the sender. */
  fromName?: string;
  /** Optional Reply-To mailbox. */
  replyTo?: string;
}

export interface MailProvider {
  readonly id: MailProviderId;
  /** Are the provider's own credentials present for this deployment? */
  isEnabled(env: Env): boolean;
  /** Credential variable names required to enable the provider. */
  readonly requiredEnv: string[];
  send(env: Env, message: MailMessage): Promise<void>;
}

const PROVIDERS: Record<MailProviderId, MailProvider> = {
  smtp: smtpProvider,
  resend: resendProvider,
  cloudflare: cloudflareProvider,
  maileroo: mailerooProvider,
  ses: sesProvider,
};

/**
 * Which provider is this deployment targeting? Returns null when nothing is
 * selected (no MAIL_PROVIDER and no legacy Resend key). Throws on an unknown
 * MAIL_PROVIDER value — a misnamed selection must not fall back quietly.
 */
export function selectedMailProviderId(env: Env): MailProviderId | null {
  const selected = env.MAIL_PROVIDER?.trim();
  if (selected === undefined || selected === "") {
    // Legacy deployments configured only RESEND_API_KEY keep working.
    return PROVIDERS.resend.isEnabled(env) ? "resend" : null;
  }
  if (!(MAIL_PROVIDER_IDS as readonly string[]).includes(selected)) {
    throw new Error(
      `MAIL_PROVIDER "${selected}" is not supported; use one of ${MAIL_PROVIDER_IDS.join(", ")}`,
    );
  }
  return selected as MailProviderId;
}

/**
 * Resolve the configured provider, or null when the deployment has none.
 * Returns the provider even when its credentials are incomplete — callers
 * that must gate on availability use `isProviderEnabled`; delivery surfaces
 * a named-missing-variable error through the provider itself.
 */
export function resolveMailProvider(env: Env): MailProvider | null {
  const id = selectedMailProviderId(env);
  if (!id) return null;
  return PROVIDERS[id];
}

/** Is the selected delivery path (provider credentials only) complete? */
export function isMailProviderEnabled(env: Env): boolean {
  const provider = resolveMailProvider(env);
  return provider !== null && provider.isEnabled(env);
}

/** Is a mail provider select-able at all in this deployment? */
export function isMailProviderConfigured(env: Env): boolean {
  try {
    return resolveMailProvider(env) !== null;
  } catch {
    // Unknown MAIL_PROVIDER: loud at delivery, but availability probing
    // should not crash unrelated code paths (e.g. 503 gating).
    return false;
  }
}

/**
 * Sender identity resolution shared by all purposes. Per-purpose variables
 * (INVITATION_EMAIL_FROM, MFA_OTP_EMAIL_FROM) win over the generic default.
 */
export function mailSender(env: Env, purposeFrom?: string): { address: string; name?: string } {
  return {
    address: purposeFrom ?? env.MAIL_FROM ?? "",
    name: env.MAIL_FROM_NAME || undefined,
  };
}

/** Named-required-variable error used when a selected provider lacks credentials. */
export function providerNotConfiguredError(provider: MailProvider): Error {
  return new Error(
    `Mail provider "${provider.id}" is selected but not configured; required: ${provider.requiredEnv.join(", ")}`,
  );
}
