/**
 * Cloudflare Email Sending provider, through the account REST API
 * (`POST /accounts/{account_id}/email/sending/send`) so the provider is
 * selectable at runtime without a new Workers binding. Authentication is a
 * Cloudflare API token with the Email Sending permission.
 */

import type { Env } from "../../env";
import { type MailMessage, type MailProvider, providerNotConfiguredError } from "../provider";
import { deliveryError } from "./shared";

export function cloudflareSendUrl(accountId: string): string {
  return `https://api.cloudflare.com/client/v4/accounts/${accountId}/email/sending/send`;
}

export const cloudflareProvider: MailProvider = {
  id: "cloudflare",
  requiredEnv: ["MAIL_CLOUDFLARE_ACCOUNT_ID", "MAIL_CLOUDFLARE_API_TOKEN"],
  isEnabled(env) {
    return Boolean(env.MAIL_CLOUDFLARE_ACCOUNT_ID && env.MAIL_CLOUDFLARE_API_TOKEN);
  },
  async send(env, message: MailMessage) {
    if (!env.MAIL_CLOUDFLARE_ACCOUNT_ID || !env.MAIL_CLOUDFLARE_API_TOKEN) {
      throw providerNotConfiguredError(cloudflareProvider);
    }
    const response = await fetch(cloudflareSendUrl(env.MAIL_CLOUDFLARE_ACCOUNT_ID), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.MAIL_CLOUDFLARE_API_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: {
          address: message.from,
          ...(message.fromName ? { name: message.fromName } : {}),
        },
        to: message.to,
        subject: message.subject,
        text: message.text,
        ...(message.html ? { html: message.html } : {}),
        ...(message.replyTo ? { reply_to: message.replyTo } : {}),
      }),
    });
    // The Cloudflare envelope carries its own success flag; a 200 with
    // success=false (or nonzero errors) is a failed delivery, not a throw
    // the caller should read as sent.
    if (!response.ok) {
      throw await deliveryError("Cloudflare email delivery failed", response);
    }
    const result = await response.json().catch(() => null) as { success?: boolean; errors?: { code: number; message: string }[] } | null;
    if (!result || result.success === false) {
      const first = result?.errors?.[0];
      const detail = first ? `${first.code} ${first.message}` : "unknown error";
      throw new Error(`Cloudflare email delivery failed — ${detail}`);
    }
  },
};
