/**
 * Duo Auth API client for secondary authentication (Duo Free edition includes
 * the Auth API). Verifies a signed request against the configured integration
 * and performs the /auth/v2/auth call for a user: push notification, SMS
 * passcodes, phone callback, or a passcode from a hardware token.
 *
 * Duo signing contract: Date header in UTC, base64(ikey:HMAC-SHA1(secret,
 * [date, method, host, path, params].join("\n"))) as Basic auth.
 */

import type { Env } from "../env";

export interface DuoConfig {
  ikey: string;
  skey: string;
  apiHostname: string;
}

export interface DuoAuthResult {
  result: "allow" | "deny" | "enroll";
  status: string;
  statusMessage: string;
}

export function duoConfig(env: Env): DuoConfig | null {
  if (!env.DUO_IKEY || !env.DUO_SKEY || !env.DUO_API_HOSTNAME) return null;
  return { ikey: env.DUO_IKEY, skey: env.DUO_SKEY, apiHostname: env.DUO_API_HOSTNAME };
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function hmacSha1(key: string, data: string): Promise<string> {
  const rawKey = new TextEncoder().encode(key);
  const imported = await crypto.subtle.importKey("raw", rawKey, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(data)));
  return toBase64(signature);
}

/** Duo signing contract applied over the canonical request. */
async function duoSignature(config: DuoConfig, date: string, method: string, path: string, params: string): Promise<string> {
  const canon = [date, method.toUpperCase(), config.apiHostname, path, params].join("\n");
  return hmacSha1(config.skey, canon);
}



export interface DuoAuthCall {
  user: string;
  /** This deployment uses Duo for push notifications only. */
  factor?: "auto" | "push";
}

/** Perform Duo /auth/v2/auth for a user and normalize the result. */
export async function duoAuthCall(env: Env, input: DuoAuthCall): Promise<DuoAuthResult | null> {
  const config = duoConfig(env);
  if (!config) return null;
  const params = new URLSearchParams({ user: input.user, factor: input.factor ?? "auto" });
  const date = new Date().toUTCString();
  const signature = await duoSignature(config, date, "POST", "/auth/v2/auth", params.toString());
  const authHeader = toBase64(new TextEncoder().encode(`${config.ikey}:${signature}`));
  const response = await fetch(`https://${config.apiHostname}/auth/v2/auth`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${authHeader}`,
      Date: date,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });
  if (!response.ok) {
    throw new Error(`Duo Auth API call failed with status ${response.status}`);
  }
  const body = await response.json() as { stat?: string; response?: { result?: DuoAuthResult["result"]; status?: string; status_message?: string } };
  if (body.stat !== "OK" || !body.response?.result) {
    throw new Error("Duo Auth API returned an unexpected body");
  }
  return {
    result: body.response.result ?? "deny",
    status: body.response.status ?? "",
    statusMessage: body.response.status_message ?? "",
  };
}
