/**
 * Resend HTTP API provider. Credentials come from `MAIL_RESEND_API_KEY`; the
 * legacy `RESEND_API_KEY` key remains supported both as a direct selection
 * fallback and as the pre-selection-compatibility default.
 */

import type { Env } from "../../env";
import { type MailMessage, type MailProvider, providerNotConfiguredError } from "../provider";
import { deliveryError, fromWithName } from "./shared";

export const RESEND_API_URL = "https://api.resend.com/emails";

export function resendApiKey(env: Env): string | undefined {
  return env.MAIL_RESEND_API_KEY ?? env.RESEND_API_KEY;
}

export const resendProvider: MailProvider = {
  id: "resend",
  requiredEnv: ["MAIL_RESEND_API_KEY"],
  isEnabled(env) {
    return Boolean(resendApiKey(env));
  },
  async send(env, message: MailMessage) {
    const apiKey = resendApiKey(env);
    if (!apiKey) throw providerNotConfiguredError(resendProvider);
    const response = await fetch(RESEND_API_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: fromWithName(message),
        to: [message.to],
        subject: message.subject,
        text: message.text,
        ...(message.html ? { html: message.html } : {}),
        ...(message.replyTo ? { reply_to: message.replyTo } : {}),
      }),
    });
    if (!response.ok) {
      throw await deliveryError("Resend email delivery failed", response);
    }
  },
};
