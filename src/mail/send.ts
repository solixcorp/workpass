/**
 * Transactional email delivery. Reuses the deployment's existing Resend
 * credentials (`RESEND_API_KEY`) with an optional per-purpose sender address
 * override. For headless local development the same webhook pattern as the
 * OTP sender is available (`INVITATION_EMAIL_WEBHOOK_URL`), which records the
 * message instead of delivering it. Fail-closed when nothing is configured:
 * callers surface the error instead of treating the message as sent.
 */

import type { Env } from "../env";

export interface TransactionEmail {
  to: string;
  subject: string;
  text: string;
}

/** Is transactional email deliverable in this deployment? */
export function transactionEmailAvailable(env: Env): boolean {
  return Boolean(env.INVITATION_EMAIL_WEBHOOK_URL || env.RESEND_API_KEY);
}

export async function sendTransactionEmail(env: Env, email: TransactionEmail): Promise<void> {
  if (env.INVITATION_EMAIL_WEBHOOK_URL) {
    const response = await fetch(env.INVITATION_EMAIL_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...email, sentAt: new Date().toISOString() }),
    });
    if (!response.ok) {
      throw new Error(`Invitation email webhook delivery failed with status ${response.status}`);
    }
    return;
  }
  const from = env.INVITATION_EMAIL_FROM ?? env.MFA_OTP_EMAIL_FROM;
  if (!env.RESEND_API_KEY || !from) {
    console.error("Transactional email is requested but no sender is configured");
    throw new Error("Transactional email is not configured");
  }
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [email.to], subject: email.subject, text: email.text }),
  });
  if (!response.ok) {
    throw new Error(`Transactional email delivery failed with status ${response.status}`);
  }
}
