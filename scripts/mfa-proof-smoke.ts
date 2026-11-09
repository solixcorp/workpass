/**
 * Operator tooling: verify the session-bound MFA proof pipeline end to end
 * against a running local workerd: TOTP enrollment, the negative case (a
 * requireMfa OIDC policy rejects authorization before any verification), the
 * proof-recording case (/two-factor/verify-totp), and the positive case (the
 * same session authorizes afterwards).
 *
 *   bun run scripts/mfa-proof-smoke.ts [--migrate-token t] [--admin-token t]
 *
 * Disposable local database and throwaway inline credentials only.
 */

interface Options {
  base: string;
  username: string;
  password: string;
  adminToken: string | null;
  migrateToken: string | null;
  dcrToken: string | null;
}

const rawArgs = Bun.argv.slice(2);
function readOption(key: string): string | null {
  const index = rawArgs.indexOf(`--${key}`);
  return index >= 0 && index + 1 < rawArgs.length ? rawArgs[index + 1]! : null;
}

const options: Options = {
  base: readOption("base") ?? "http://127.0.0.1:8787",
  username: readOption("username") ?? "benchadmin",
  password: readOption("password") ?? "BenchOnly-7d9Kpw9zL2",
  adminToken: readOption("admin-token"),
  migrateToken: readOption("migrate-token"),
  dcrToken: readOption("dcr-token") ?? "operator-provisioned-dcr-token-0123456789abcdef",
};
const base = new URL(options.base).origin;

const jar = new Map<string, string>();
function absorb(response: Response): void {
  for (const header of response.headers.getSetCookie()) {
    const pair = header.split(";")[0]!;
    const separator = pair.indexOf("=");
    jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}
function cookiePair(): string {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}
async function call(path: string, init?: { method?: "GET" | "POST" | "DELETE" | "PUT"; body?: unknown; headers?: Record<string, string> }): Promise<Response> {
  const response = await fetch(`${base}${path}`, {
    method: init?.method ?? "GET",
    headers: {
      Origin: base,
      ...(cookiePair() ? { Cookie: cookiePair() } : {}),
      ...(init?.body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(init?.headers ?? {}),
    },
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    redirect: "manual",
  });
  absorb(response);
  return response;
}
function expect(step: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`PASS ${step}`);
    return;
  }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 400));
  process.exit(1);
}

// --- TOTP generation (RFC 4226/6238 over SHA-1, 30s window, 6 digits) --------
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32ToBytes(value: string): Uint8Array {
  let bits = 0;
  let accumulator = 0;
  const output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = BASE32.indexOf(char);
    if (index < 0) throw new Error("Invalid base32 in TOTP secret");
    accumulator = (accumulator << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((accumulator >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(output);
}
async function totpCode(secret: Uint8Array, counter: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
  const rawKey = new ArrayBuffer(secret.length);
  new Uint8Array(rawKey).set(secret);
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes.buffer));
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(binary % 1_000_000).padStart(6, "0");
}

async function verifyTotpWithRetry(secret: Uint8Array): Promise<Response> {
  // Attempt the current window first, then neighbours, to survive a boundary.
  const current = Math.floor(Date.now() / 30_000);
  for (const offset of [0, 1, -1]) {
    const code = await totpCode(secret, current + offset);
    const response = await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code } });
    if (response.status === 200) return response;
    console.log(`INFO verify-totp window ${offset} got ${response.status}`);
  }
  return await call("/api/auth/two-factor/verify-totp", { method: "POST", body: { code: "000000" } });
}

// --- setup -------------------------------------------------------------------
if (options.migrateToken) {
  const migrate = await fetch(`${base}/_internal/migrate`, { method: "POST", headers: { Authorization: `Bearer ${options.migrateToken}` } });
  expect("migration", migrate.status === 200, await migrate.text());
}
if (options.adminToken) {
  const bootstrap = await fetch(`${base}/api/admin/bootstrap`, {
    method: "POST",
    headers: { Authorization: `Bearer ${options.adminToken}`, "Content-Type": "application/json", Origin: base },
    body: JSON.stringify({ email: "bench-admin@example.com", name: "Bench Admin", username: options.username, password: options.password }),
  });
  expect("bootstrap", [201, 409].includes(bootstrap.status), await bootstrap.text());
}

const signIn = await call("/api/auth/sign-in/username", { method: "POST", body: { username: options.username, password: options.password } });
expect("sign-in", signIn.status === 200, signIn.status);

const enable = await call("/api/auth/two-factor/enable", { method: "POST", body: { password: options.password, method: "totp" } });
const enableBody = await enable.json().catch(() => ({})) as { totpURI?: string };
expect("totp enrollment returns a uri", enable.status === 200 && !!enableBody.totpURI, enable.status);
const secret = base32ToBytes(new URL(enableBody.totpURI!).searchParams.get("secret") ?? "");
expect("secret parsed", secret.length >= 10, enableBody.totpURI);

const register = await fetch(`${base}/api/auth/oauth2/register`, {
  method: "POST",
  headers: { Authorization: `Bearer ${options.dcrToken}`, "Content-Type": "application/json", Origin: base, ...(cookiePair() ? { Cookie: cookiePair() } : {}) },
  body: JSON.stringify({ client_name: "mfa-proof-probe", redirect_uris: ["https://rp-mfa-proof.test/cb"], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile email" }),
});
const registerBody = await register.json() as { client_id?: string };
expect("client registered", register.status === 201 && !!registerBody.client_id, register.status);

const policy = await call("/api/admin/app-access-policies", { method: "PUT", headers: { Origin: base }, body: {
  subject: `oidc:${registerBody.client_id}`,
  allowedMethods: "password,passkey",
  sessionTtlSeconds: null,
  bypassWindowSeconds: 0,
  enforcementMode: "enforce",
  requireMfa: true,
  groups: [],
} });
expect("requireMfa policy saved", policy.status === 200, await policy.text());

const verifier = "mfa-proof-verifier-mfa-proof-verifier-mfa-proof-42";
const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
const authorizePath = `/api/auth/oauth2/authorize?${new URLSearchParams({
  client_id: registerBody.client_id!,
  redirect_uri: "https://rp-mfa-proof.test/cb",
  response_type: "code",
  scope: "openid profile email",
  state: "s1",
  nonce: "n1",
  code_challenge: challenge,
  code_challenge_method: "S256",
})}`;

// --- negative case: enrollment alone must not satisfy the policy -------------
const denied = await call(authorizePath);
expect("authorize denied before verification", denied.status === 403, denied.status);
expect("no code leaked before verification", !(await denied.text()).includes("code="));

// --- proof recording: the verification IS the proof ---------------------------
const verified = await verifyTotpWithRetry(secret);
const verifyBody = await verified.clone().json().catch(() => ({})) as { token?: string };
expect("verify-totp accepted", verified.status === 200, verified.status);
expect("verify response carries the verified session", typeof verifyBody.token === "string" && verifyBody.token.length > 0);

// --- positive case: the same session now authorizes --------------------------
const allowed = await call(authorizePath);
expect("authorize continues with the session proof", allowed.status === 302, { status: allowed.status, body: (await allowed.text()).slice(0, 200) });

// --- cleanup ------------------------------------------------------------------
const disable = await call("/api/auth/two-factor/disable", { method: "POST", body: { password: options.password, all: true } });
if (disable.status === 200) console.log("PASS totp disabled (cleanup)");
else console.log(`INFO totp disable not performed (${disable.status}); disposable environment, tolerated`);
const policyRemoved = await call(`/api/admin/app-access-policies/${encodeURIComponent(`oidc:${registerBody.client_id}`)}`, { method: "DELETE", headers: { Origin: base } });
if (policyRemoved.ok) console.log("PASS policy removed (cleanup)");

console.log("mfa proof smoke OK: enrollment, pre-verification denial, proof recording, post-verification authorization.");
