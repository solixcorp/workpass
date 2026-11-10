/**
 * Amazon SES v2 provider (`POST /v2/email/outbound-emails`, Simple content).
 * Requests carry SigV4 signatures computed with Web Crypto — no AWS SDK
 * dependency. Credentials read from MAIL_SES_* with the standard
 * AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY fallbacks so workerd-style env
 * conventions still work. SES templates are deliberately unused.
 */

import type { Env } from "../../env";
import { type MailMessage, type MailProvider, providerNotConfiguredError } from "../provider";
import { deliveryError, fromWithName } from "./shared";

const SES_PATH = "/v2/email/outbound-emails";

export function sesEndpoint(env: Env): string {
  const override = env.MAIL_SES_ENDPOINT?.trim();
  return override ? override.replace(/\/+$/, "") : `https://email.${env.MAIL_SES_REGION}.amazonaws.com`;
}

function sesCredentials(env: Env): { accessKeyId: string; secretAccessKey: string } | null {
  const accessKeyId = env.MAIL_SES_ACCESS_KEY_ID ?? env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = env.MAIL_SES_SECRET_ACCESS_KEY ?? env.AWS_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) return null;
  return { accessKeyId, secretAccessKey };
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(data: string): Promise<string> {
  return hexEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data))));
}

async function hmacSha256(key: Uint8Array, data: string): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", toArrayBuffer(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(data)));
}

/** SubtleCrypto wants a real ArrayBuffer; copy views so byte offsets are honored. */
function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

export interface SesSignedRequest {
  url: string;
  amzDate: string;
  authorization: string;
  payloadHash: string;
}

/**
 * Build the SigV4 signed request for an SES SendEmail call. Exported pure:
 * canonical request construction is covered by known-input tests.
 */
export async function signSesRequest(
  env: Env,
  payload: string,
  now: Date,
): Promise<SesSignedRequest> {
  const credentials = sesCredentials(env);
  const region = env.MAIL_SES_REGION?.trim() ?? "";
  if (!credentials || !region) throw providerNotConfiguredError(sesProvider);
  const url = `${sesEndpoint(env)}${SES_PATH}`;
  const host = new URL(url).host;

  const stamp = now.toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z"; // YYYYMMDDTHHMMSSZ
  const dateStamp = stamp.slice(0, 8);
  const payloadHash = await sha256Hex(payload);

  const signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
  const canonicalHeaders = [
    `content-type:application/json\n`,
    `host:${host}\n`,
    `x-amz-content-sha256:${payloadHash}\n`,
    `x-amz-date:${stamp}\n`,
  ].join("");
  const canonicalRequest = ["POST", SES_PATH, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");

  const scope = `${dateStamp}/${region}/ses/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    stamp,
    scope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  const encoder = new TextEncoder();
  let signingKey = await hmacSha256(encoder.encode(`AWS4${credentials.secretAccessKey}`), dateStamp);
  signingKey = await hmacSha256(signingKey, region);
  signingKey = await hmacSha256(signingKey, "ses");
  signingKey = await hmacSha256(signingKey, "aws4_request");
  const signature = hexEncode(await hmacSha256(signingKey, stringToSign));

  const authorization = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { url, amzDate: stamp, authorization, payloadHash };
}

export const sesProvider: MailProvider = {
  id: "ses",
  requiredEnv: ["MAIL_SES_REGION", "MAIL_SES_ACCESS_KEY_ID", "MAIL_SES_SECRET_ACCESS_KEY"],
  isEnabled(env) {
    return Boolean(env.MAIL_SES_REGION && sesCredentials(env));
  },
  async send(env, message: MailMessage) {
    if (!env.MAIL_SES_REGION || !sesCredentials(env)) throw providerNotConfiguredError(sesProvider);
    const payload = JSON.stringify({
      FromEmailAddress: fromWithName(message),
      Destination: { ToAddresses: [message.to] },
      ...(message.replyTo ? { ReplyToAddresses: [message.replyTo] } : {}),
      Content: {
        Simple: {
          Subject: { Data: message.subject, Charset: "UTF-8" },
          Body: {
            Text: { Data: message.text, Charset: "UTF-8" },
            ...(message.html ? { Html: { Data: message.html, Charset: "UTF-8" } } : {}),
          },
        },
      },
    });
    const signed = await signSesRequest(env, payload, new Date());
    const response = await fetch(signed.url, {
      method: "POST",
      headers: {
        Authorization: signed.authorization,
        "Content-Type": "application/json",
        "X-Amz-Date": signed.amzDate,
        "X-Amz-Content-Sha256": signed.payloadHash,
      },
      body: payload,
    });
    if (!response.ok) {
      throw await deliveryError("SES email delivery failed", response);
    }
  },
};
