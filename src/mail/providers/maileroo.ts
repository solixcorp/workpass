/**
 * Maileroo provider, through the basic email API
 * (`POST https://smtp.maileroo.com/api/v2/emails`). Template and bulk
 * endpoints are deliberately unused — this IdP sends code invitations and
 * OTP passcodes it composes itself.
 */

import type { Env } from "../../env";
import { type MailMessage, type MailProvider, providerNotConfiguredError } from "../provider";
import { deliveryError } from "./shared";

export const MAILEROO_API_URL = "https://smtp.maileroo.com/api/v2/emails";

export const mailerooProvider: MailProvider = {
  id: "maileroo",
  requiredEnv: ["MAIL_MAILEROO_API_KEY"],
  isEnabled(env) {
    return Boolean(env.MAIL_MAILEROO_API_KEY);
  },
  async send(env, message: MailMessage) {
    if (!env.MAIL_MAILEROO_API_KEY) throw providerNotConfiguredError(mailerooProvider);
    const response = await fetch(MAILEROO_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.MAIL_MAILEROO_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: {
          address: message.from,
          ...(message.fromName ? { display_name: message.fromName } : {}),
        },
        to: [{ address: message.to }],
        subject: message.subject,
        plain: message.text,
        ...(message.html ? { html: message.html } : {}),
        ...(message.replyTo ? { reply_to: [{ address: message.replyTo }] } : {}),
      }),
    });
    // 413 (payload too large) and 503 (queue unavailable, Retry-After)
    // are worth naming distinctly: neither would be fixed by retrying
    // immediately, and the 413 case must never be re-read as sent.
    if (response.status === 413) {
      throw new Error("Maileroo email delivery failed: payload exceeds the maximum size (413)");
    }
    if (response.status === 503) {
      throw new Error("Maileroo email delivery failed: queue unavailable (503)");
    }
    if (!response.ok) {
      throw await deliveryError("Maileroo email delivery failed", response);
    }
    const result = await response.json().catch(() => null) as { success?: boolean; message?: string } | null;
    if (!result || result.success === false) {
      throw new Error(`Maileroo email delivery failed — ${result?.message ?? "unknown error"}`);
    }
  },
};
