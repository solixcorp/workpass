/**
 * Generic SMTP provider. Any authenticated relay (including Cloudflare Email
 * Sending SMTP at smtp.mx.cloudflare.net:465 or Maileroo's SMTP relay) works
 * through here: implicit TLS on 465 by default, STARTTLS on 587 by default.
 * Plaintext is only reachable by explicitly setting MAIL_SMTP_SECURE=false
 * with STARTTLS unset — credential-bearing plaintext is operator-acknowledged
 * configuration, not a silent fallback.
 */

import type { Env } from "../../env";
import { type MailMessage, type MailProvider, providerNotConfiguredError } from "../provider";
import { sendSmtpMail, type SmtpOptions, type SmtpTransport } from "./smtp/client";

export function resolveSmtpTransport(env: Env): SmtpTransport {
  if (env.MAIL_SMTP_SECURE === "true") return "implicit_tls";
  if (env.MAIL_SMTP_STARTTLS === "true") return "starttls";
  const port = smtpPort(env);
  if (port === 465) return "implicit_tls";
  if (port === 587) return "starttls";
  return env.MAIL_SMTP_SECURE === "false" ? "off" : "starttls";
}

export function smtpPort(env: Env): number {
  const parsed = Number(env.MAIL_SMTP_PORT ?? "");
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 465;
}

export function smtpOptions(env: Env): SmtpOptions {
  const credentials = env.MAIL_SMTP_USERNAME || env.MAIL_SMTP_PASSWORD
    ? { username: env.MAIL_SMTP_USERNAME ?? "", password: env.MAIL_SMTP_PASSWORD ?? "" }
    : undefined;
  let ehloName = "[127.0.0.1]";
  try {
    ehloName = new URL(env.AUTH_BASE_URL).hostname;
  } catch {
    // Unparseable base URL: keep the placeholder client name.
  }
  return {
    host: env.MAIL_SMTP_HOST!,
    port: smtpPort(env),
    transport: resolveSmtpTransport(env),
    ...(credentials ? { credentials } : {}),
    ehloName,
  };
}

export const smtpProvider: MailProvider = {
  id: "smtp",
  requiredEnv: ["MAIL_SMTP_HOST"],
  isEnabled(env) {
    return Boolean(env.MAIL_SMTP_HOST);
  },
  async send(env, message: MailMessage) {
    if (!env.MAIL_SMTP_HOST) throw providerNotConfiguredError(smtpProvider);
    await sendSmtpMail(smtpOptions(env), message);
  },
};
