/**
 * Transactional email dispatch on top of the provider registry. Every purpose
 * (invitation, OTP) goes through `deliverMessage`, which honors one
 * purpose-supplied dev/webhook override that records the message instead of
 * delivering it (headless local testing), then the selected provider. The
 * sender identity is resolved per purpose; delivery fails closed when no
 * provider is configured or the sender is unset — callers surface the error
 * instead of treating the message as sent.
 */

import type { Env } from "../env";
import {
  isMailProviderEnabled,
  resolveMailProvider,
  type MailMessage,
  providerNotConfiguredError,
} from "./provider";

/** Is transactional email deliverable in this deployment (webhook or provider)? */
export function transactionEmailAvailable(env: Env): boolean {
  return Boolean(env.INVITATION_EMAIL_WEBHOOK_URL) || Boolean(resolveMailProvider(env) && isMailProviderEnabled(env));
}

/**
 * Dev/mock webhook override: record the message at a receiver URL instead of
 * delivering it. `webhookPayload` lets callers keep their established body
 * shape (the OTP path records the raw code alongside the message); without
 * one the standard message fields are recorded. When `webhookUrl` is absent
 * the message goes to the selected provider. Delivery fails closed when no
 * provider is configured or the sender is unset — callers surface the error
 * instead of treating the message as sent.
 */
export async function deliverMessage(
  env: Env,
  message: MailMessage,
  options: { purpose: string; webhookUrl?: string; webhookPayload?: Record<string, unknown> },
): Promise<void> {
  if (options.webhookUrl) {
    const response = await fetch(options.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...(options.webhookPayload ?? { to: message.to, subject: message.subject, text: message.text, from: message.from }),
        sentAt: new Date().toISOString(),
      }),
    });
    if (!response.ok) {
      throw new Error(`${options.purpose} email webhook delivery failed with status ${response.status}`);
    }
    return;
  }
  const provider = resolveMailProvider(env);
  if (!provider || !provider.isEnabled(env)) {
    if (provider && !provider.isEnabled(env)) {
      throw providerNotConfiguredError(provider);
    }
    console.error(`${options.purpose} email delivery is requested but no provider is configured`);
    throw new Error("Email delivery is not configured");
  }
  if (!message.from) {
    console.error(`${options.purpose} email delivery is requested but no sender address is configured`);
    throw new Error("Email sender address is not configured");
  }
  // Reply-To is a global concern (MAIL_REPLY_TO), applied centrally here.
  const replyTo = env.MAIL_REPLY_TO || undefined;
  await provider.send(env, replyTo ? { ...message, replyTo } : message);
}

export interface TransactionEmail {
  to: string;
  subject: string;
  text: string;
}

export async function sendTransactionEmail(env: Env, email: TransactionEmail): Promise<void> {
  const from = env.INVITATION_EMAIL_FROM ?? env.MAIL_FROM ?? env.MFA_OTP_EMAIL_FROM ?? "";
  await deliverMessage(env, { ...email, from }, {
    purpose: "Invitation",
    webhookUrl: env.INVITATION_EMAIL_WEBHOOK_URL,
  });
}
