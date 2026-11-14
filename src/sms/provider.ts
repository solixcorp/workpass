/**
 * SMS delivery behind one function. The provider comes from SMS_PROVIDER (set
 * by an administrator in the console or by the deployment); a deployment that
 * only has MFA_SMS_WEBHOOK_URL keeps working as a webhook. Fails closed.
 */

import type { Env } from "../env";

export const SMS_PROVIDER_IDS = ["twilio", "solapi", "webhook"] as const;
export type SmsProviderId = (typeof SMS_PROVIDER_IDS)[number];

export function selectedSmsProvider(env: Env): SmsProviderId | null {
  const chosen = env.SMS_PROVIDER?.trim();
  if (chosen) return (SMS_PROVIDER_IDS as readonly string[]).includes(chosen) ? (chosen as SmsProviderId) : null;
  return env.MFA_SMS_WEBHOOK_URL ? "webhook" : null;
}

/** Are the selected provider's credentials all present? */
export function smsAvailable(env: Env): boolean {
  switch (selectedSmsProvider(env)) {
    case "twilio": return Boolean(env.SMS_TWILIO_ACCOUNT_SID && env.SMS_TWILIO_AUTH_TOKEN && env.SMS_FROM);
    case "solapi": return Boolean(env.SMS_SOLAPI_API_KEY && env.SMS_SOLAPI_API_SECRET && env.SMS_FROM);
    case "webhook": return Boolean(env.MFA_SMS_WEBHOOK_URL);
    default: return false;
  }
}

async function failure(prefix: string, response: Response): Promise<Error> {
  let detail = "";
  try {
    const text = await response.text();
    detail = text.length > 300 ? `${text.slice(0, 300)}…` : text;
  } catch { /* the status alone is still useful */ }
  return new Error(detail ? `${prefix}: ${response.status} — ${detail}` : `${prefix}: ${response.status}`);
}

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sendTwilio(env: Env, to: string, text: string): Promise<void> {
  const sid = env.SMS_TWILIO_ACCOUNT_SID!;
  const from = env.SMS_FROM!;
  const body = new URLSearchParams({ To: to, Body: text });
  body.set(from.startsWith("MG") ? "MessagingServiceSid" : "From", from);
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`, {
    method: "POST",
    headers: { Authorization: `Basic ${btoa(`${sid}:${env.SMS_TWILIO_AUTH_TOKEN}`)}`, "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) throw await failure("Twilio SMS delivery failed", response);
}

async function sendSolapi(env: Env, to: string, text: string): Promise<void> {
  // Solapi sends to domestic numbers: +8210… becomes 010….
  if (!to.startsWith("+82")) throw new Error("솔라피는 +82 번호로만 보낼 수 있습니다.");
  const local = `0${to.slice(3)}`;
  const date = new Date().toISOString();
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)).buffer);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.SMS_SOLAPI_API_SECRET!), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(date + salt)));
  const response = await fetch("https://api.solapi.com/messages/v4/send", {
    method: "POST",
    headers: {
      Authorization: `HMAC-SHA256 apiKey=${env.SMS_SOLAPI_API_KEY}, date=${date}, salt=${salt}, signature=${signature}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ message: { to: local, from: env.SMS_FROM, text } }),
  });
  if (!response.ok) throw await failure("Solapi SMS delivery failed", response);
}

async function sendWebhook(env: Env, to: string, text: string, code: string | null): Promise<void> {
  const response = await fetch(env.MFA_SMS_WEBHOOK_URL!, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(env.SMS_WEBHOOK_TOKEN ? { Authorization: `Bearer ${env.SMS_WEBHOOK_TOKEN}` } : {}) },
    body: JSON.stringify({ to, ...(code ? { code } : {}), text, sentAt: new Date().toISOString() }),
  });
  if (!response.ok) throw new Error(`SMS webhook delivery failed with status ${response.status}`);
}

/** Send one text message. `code` is passed to a webhook next to the text, as before. */
export async function sendSms(env: Env, input: { to: string; text: string; code?: string | null }): Promise<void> {
  if (!smsAvailable(env)) throw new Error("SMS delivery is not configured");
  const provider = selectedSmsProvider(env);
  try {
    switch (provider) {
      case "twilio": return await sendTwilio(env, input.to, input.text);
      case "solapi": return await sendSolapi(env, input.to, input.text);
      default: return await sendWebhook(env, input.to, input.text, input.code ?? null);
    }
  } catch (error) {
    // Callers report a generic failure to the person; the cause stays in the logs.
    console.error("sms delivery failed", provider, error instanceof Error ? error.message : String(error));
    throw error;
  }
}
