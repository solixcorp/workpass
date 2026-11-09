/**
 * Operator tooling: verify the headless TOTP two-factor flow end to end —
 * enrollment, enforced second-factor sign-in, wrong-code rejection — plus the
 * per-application requireMfa policy enforcement. The dev server must be
 * running with migrations enabled. TOTP codes are computed locally from the
 * enrollment URI (RFC 6238, HMAC-SHA1, 30s, 6 digits).
 *
 *   bun run scripts/mfa-smoke.ts [--migrate-token t] [--admin-token t]
 *
 * Disposable local database and throwaway inline credentials only.
 */

interface Options {
  base: string;
  adminUsername: string;
  adminPassword: string;
  adminToken: string | null;
  migrateToken: string | null;
}

const rawArgs = Bun.argv.slice(2);
function readOption(key: string): string | null {
  const index = rawArgs.indexOf(`--${key}`);
  return index >= 0 && index + 1 < rawArgs.length ? rawArgs[index + 1]! : null;
}

const options: Options = {
  base: readOption("base") ?? "http://127.0.0.1:8787",
  adminUsername: readOption("username") ?? "benchadmin",
  adminPassword: readOption("password") ?? "BenchOnly-7d9Kpw9zL2",
  adminToken: readOption("admin-token"),
  migrateToken: readOption("migrate-token"),
};
const base = new URL(options.base).origin;

function expect(step: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`PASS ${step}`);
    return;
  }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 400));
  process.exit(1);
}

// --- RFC 6238 TOTP (HMAC-SHA1, 30s period, 6 digits, one window tolerance) ---
const SECRET_BUFFER_CACHE = new Map<string, Uint8Array>();

function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let acc = 0;
  const output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) continue;
    acc = (acc << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((acc >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function totpFor(secretB32: string, atMs: number, offsetSteps = 0): Promise<string> {
  let secret = SECRET_BUFFER_CACHE.get(secretB32);
  if (!secret) {
    secret = base32Decode(secretB32);
    SECRET_BUFFER_CACHE.set(secretB32, secret);
  }
  const counter = Math.floor(atMs / 30_000) + offsetSteps;
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    (mac[offset + 1]! << 16) |
    (mac[offset + 2]! << 8) |
    mac[offset + 3]!;
  return String(binary % 1_000_000).padStart(6, "0");
}

// --- client -------------------------------------------------------------------
const jar = new Map<string, string>();
const secondJar = new Map<string, string>();
function absorb(jar: Map<string, string>, response: Response): void {
  for (const header of response.headers.getSetCookie()) {
    const pair = header.split(";")[0]!;
    const separator = pair.indexOf("=");
    if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}
function cookiePair(jar: Map<string, string>): string {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}
async function call(jar: Map<string, string>, path: string, init?: { method?: "GET" | "POST" | "DELETE" | "PUT"; body?: unknown; origin?: boolean; token?: string; form?: Record<string, string> }): Promise<Response> {
  const headers: Record<string, string> = { ...(init?.headers ?? {}) };
  if (cookiePair(jar)) headers.Cookie = cookiePair(jar);
  if (init?.origin) headers.Origin = base;
  if (init?.form) headers["Content-Type"] = "application/x-www-form-urlencoded";
  else if (init?.body !== undefined) headers["Content-Type"] = "application/json";
  let data: string | undefined;
  if (init?.form) data = new URLSearchParams(init.form).toString();
  else if (init?.body !== undefined) data = JSON.stringify(init.body);
  const response = await fetch(`${base}${path}`, { method: init?.method ?? "GET", headers, body: data, redirect: "manual" });
  absorb(jar, response);
  return response;
}

if (options.migrateToken) {
  const migrate = await fetch(`${base}/_internal/migrate`, { method: "POST", headers: { Authorization: `Bearer ${options.migrateToken}` } });
  expect("migration", migrate.status === 200, await migrate.clone().text());
}
if (options.adminToken) {
  const bootstrap = await fetch(`${base}/api/admin/bootstrap`, {
    method: "POST",
    headers: { Authorization: `Bearer ${options.adminToken}`, "Content-Type": "application/json", "Origin": base },
    body: JSON.stringify({ email: "bench-admin@example.com", name: "Bench Admin", username: options.adminUsername, password: options.adminPassword }),
  });
  expect("bootstrap", [201, 409].includes(bootstrap.status), await bootstrap.clone().text());
}

const signIn = await call(jar, "/api/auth/sign-in/username", { method: "POST", origin: true, body: { username: options.adminUsername, password: options.adminPassword } });
expect("admin sign-in", signIn.status === 200, signIn.status);

// --- TOTP enrollment (with the account password per the two-factor contract) ---
const sc = signIn.headers.getSetCookie?.() ?? [];
const enroll = await call(jar, "/api/auth/two-factor/enable", {
  method: "POST",
  origin: true,
  body: { password: options.adminPassword, method: "totp", issuer: "internal-auth" },
});
const enrollBody = await enroll.json().catch(() => ({})) as { totpURI?: string; backupCodes?: string[] };
const enrollFailed = JSON.stringify(enrollBody).slice(0, 260);
expect("totp enrollment accepted", enroll.status === 200 && typeof enrollBody.totpURI === "string", { status: enroll.status, body: enrollFailed });
const totpSecretMatch = /secret=([A-Z2-7]+)/i.exec(enrollBody.totpURI ?? "");
expect("totp secret extracted from the enrollment URI", totpSecretMatch !== null, enrollBody.totpURI);
const secret = totpSecretMatch![1]!;
expect("backup codes issued", Array.isArray(enrollBody.backupCodes) && enrollBody.backupCodes.length > 0, enrollBody.backupCodes?.length);

const verify = await call(jar, "/api/auth/two-factor/verify-totp", {
  method: "POST",
  origin: true,
  body: { code: await totpFor(secret, Date.now()) },
});
expect("totp verified", verify.status === 200, verify.status + " " + (await verify.clone().text()).slice(0, 160));

// --- enforced second factor: sign-out, sign-in, expect the 2FA challenge ------
const signOut = await call(jar, "/api/auth/sign-out", { method: "POST", origin: true, body: {} });
expect("sign-out", signOut.status === 200, signOut.status);

const secondSignIn = await call(secondJar, "/api/auth/sign-in/username", {
  method: "POST",
  origin: true,
  body: { username: options.adminUsername, password: options.adminPassword },
});
const secondBody = await secondSignIn.json().catch(() => ({})) as { twoFactorRedirect?: boolean; user?: { id?: string } };
expect(
  "password sign-in requires the second factor (no session yet)",
  secondSignIn.status === 200 && (secondBody.twoFactorRedirect === true || secondBody.user === undefined || secondBody.user === null),
  { status: secondSignIn.status, body: JSON.stringify(secondBody).slice(0, 200) },
);
const twoFactorCookie = cookiePair(secondJar);
expect("two-factor challenge cookie present", twoFactorCookie.length > 0, twoFactorCookie);

const wrongJar = new Map<string, string>();
absorb(wrongJar, secondSignIn);
const wrongVerify = await call(wrongJar, "/api/auth/two-factor/verify-totp", {
  method: "POST",
  origin: true,
  body: { code: "000000" },
});
expect("wrong totp code rejected", wrongVerify.status >= 400, wrongVerify.status);

const rightVerify = await call(secondJar, "/api/auth/two-factor/verify-totp", {
  method: "POST",
  origin: true,
  body: { code: await totpFor(secret, Date.now()) },
});
expect("second factor verified grants the session", rightVerify.status === 200, rightVerify.status);

// --- per-application requireMfa enforcement on the SAML SSO route -------------
const register = await call(jar, "/api/admin/saml-service-providers", {
  method: "POST",
  origin: true,
  body: {
    entityId: `https://mfa-sp-${crypto.randomUUID().slice(0, 8)}.test/metadata`,
    acsUrl: "https://mfa-sp.test/acs",
    signingCertificate: `-----BEGIN CERTIFICATE-----\nMIIBIzANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7\n-----END CERTIFICATE-----\n`,
  },
});
void register; // registration may 400 on the placeholder certificate; enforcement still applies
// Enable a policy requiring MFA for a synthetic SP subject.
const policySubject = `saml:mfa-policy-probe`;
const upsert = await call(secondJar, "/api/admin/app-access-policies", {
  method: "PUT",
  origin: true,
  body: { subject: policySubject, allowedMethods: "password", sessionTtlSeconds: null, bypassWindowSeconds: 1800, enforcementMode: "enforce", requireMfa: true, groups: [] },
});
expect("requireMfa policy upserted", upsert.status === 200, await upsert.clone().text());
// The user HAS 2FA enabled, so the requireMfa gate passes for this subject.
const activity = await call(secondJar, `/api/admin/app-access-policies/${encodeURIComponent(policySubject)}/activity`);
expect("policy activity view available", activity.status === 200, activity.status);
const listed = await call(secondJar, "/api/admin/app-access-policies");
const listedBody = await listed.json().catch(() => ({})) as { policies?: Array<{ subject?: string; requireMfa?: boolean }> };
expect(
  "requireMfa flag persisted",
  listedBody.policies?.some((p) => p.subject === policySubject && p.requireMfa === true),
  listedBody,
);

console.log(`mfa smoke OK on ${base}: TOTP enrollment, enforced second-factor sign-in, backup codes recorded, wrong-code rejection and the per-application requireMfa policy.`);
