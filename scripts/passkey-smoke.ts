/**
 * Operator tooling: exercise the Better Auth passkey plugin's server-side
 * verification path on a running local workerd instance without a browser.
 * A synthetic software authenticator performs both ceremonies:
 *
 *   bun run scripts/passkey-smoke.ts [--base <url>] --password <pw>
 *
 * The script bootstraps a disposable administrator when the user table is
 * empty, signs in, registers a synthetic ES256 passkey with "none"
 * attestation, and then authenticates with that credential. Run against a
 * throwaway local database only; the synthetic credential is not a hardware
 * device and proves the server verification path, not the browser client.
 */

interface Options {
  base: string;
  username: string;
  password: string;
  email: string;
  name: string;
  adminToken: string | null;
  migrateToken: string | null;
}

const rawArgs = Bun.argv.slice(2);
function readOption(name: string): string | null {
  const index = rawArgs.indexOf(`--${name}`);
  return index >= 0 && index + 1 < rawArgs.length ? rawArgs[index + 1]! : null;
}

const options: Options = {
  base: readOption("base") ?? "http://127.0.0.1:8787",
  username: readOption("username") ?? "benchadmin",
  password: readOption("password") ?? "BenchOnly-7d9Kpw9zL2",
  email: readOption("email") ?? "bench-admin@example.com",
  name: readOption("name") ?? "Bench Admin",
  adminToken: readOption("admin-token"),
  migrateToken: readOption("migrate-token"),
};
const baseOrigin = new URL(options.base).origin;

// --- cookie jar ------------------------------------------------------------
const jar = new Map<string, string>();

function absorbCookies(response: Response): void {
  const setCookieList = response.headers.getSetCookie();
  for (const header of setCookieList) {
    const pair = header.split(";")[0]!;
    const separator = pair.indexOf("=");
    if (separator <= 0) continue;
    jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}

function cookieHeader(): string {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}

async function call(path: string, init?: { method?: "GET" | "POST"; body?: unknown; origin?: boolean }): Promise<Response> {
  const headers = new Headers();
  if (cookieHeader()) headers.set("Cookie", cookieHeader());
  if (init?.origin) headers.set("Origin", baseOrigin);
  if (init?.body !== undefined) headers.set("Content-Type", "application/json");
  const response = await fetch(`${options.base}${path}`, {
    method: init?.method ?? "GET",
    headers,
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });
  absorbCookies(response);
  return response;
}

// --- base64url and DER helpers --------------------------------------------
function toBase64Url(value: string | Uint8Array): string {
  const bytes = typeof value === "string" ? utf8Bytes(value) : value;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".slice(0, (4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((length, part) => length + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return crypto.subtle.digest("SHA-256", bytes).then((digest) => new Uint8Array(digest));
}

/** IEEE-P1363 r||s into the ASN.1 DER signature WebAuthn transports. */
function rawToDerSignature(raw: Uint8Array): Uint8Array {
  const r = raw.slice(0, raw.length / 2);
  const s = raw.slice(raw.length / 2);
  const derInt = (component: Uint8Array): number[] => {
    let start = 0;
    while (start < component.length - 1 && component[start] === 0) start += 1;
    let value = Array.from(component.slice(start));
    if ((value[0]! & 0x80) !== 0) value = [0, ...value];
    return [0x02, value.length, ...value];
  };
  const body = [...derInt(r), ...derInt(s)];
  return new Uint8Array([0x30, body.length, ...body]);
}

// --- minimal CBOR (text, bytes, small ints, small maps) --------------------
function cborEncode(value: Cbor): Uint8Array {
  return new Uint8Array(cborBytes(value));
}

type Cbor = string | Uint8Array | number | Map<Cbor, Cbor> | Map<number, number | Uint8Array>;

function cborBytes(value: Cbor): number[] {
  if (typeof value === "string") {
    const bytes = utf8Bytes(value);
    return [...head(bytes.length, 0x60), ...bytes];
  }
  if (value instanceof Uint8Array) {
    return [...head(value.length, 0x40), ...value];
  }
  if (typeof value === "number") {
    if (value >= 0) return head(value, 0x00);
    return head(-1 - value, 0x20);
  }
  const entries = Array.from(value.entries());
  return [...head(entries.length, 0xa0), ...entries.flatMap(([key, item]) => [...cborBytes(key), ...cborBytes(item)])];
}

function head(length: number, major: number): number[] {
  if (length < 24) return [major | length];
  if (length < 0x100) return [major | 24, length];
  if (length < 0x10000) return [major | 25, length >> 8, length & 0xff];
  return [major | 26, length >>> 24, (length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff];
}

// --- synthetic authenticator ----------------------------------------------
const AAGUID = new Uint8Array(16); // zeros: no specific device
const CREDENTIAL_ID = crypto.getRandomValues(new Uint8Array(32));
const credentialKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
if (!credentialKeyPair.privateKey || !credentialKeyPair.publicKey) throw new Error("EC key generation failed");

let signatureCounter = 0;

function coseEs256PublicKeyBytes(): Promise<Uint8Array> {
  return crypto.subtle.exportKey("jwk", credentialKeyPair.publicKey).then((jwk) => {
    const x = fromBase64Url(jwk.x!);
    const y = fromBase64Url(jwk.y!);
    const map = new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, x],
      [-3, y],
    ]);
    return cborEncode(map);
  });
}

async function authenticatorData(rpId: string, flags: number, withCredentialData: boolean): Promise<Uint8Array> {
  const rpIdHash = await sha256(utf8Bytes(rpId));
  signatureCounter += 1;
  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, signatureCounter, false);
  let attested = new Uint8Array(0);
  if (withCredentialData) {
    const credential = CREDENTIAL_ID;
    attested = concat(
      AAGUID,
      new Uint8Array([0x00, credential.length]),
      credential,
      await coseEs256PublicKeyBytes(),
    );
  }
  return concat(rpIdHash, new Uint8Array([flags]), counter, attested);
}

async function verifySignatureForClientData(authData: Uint8Array, clientDataJSON: string): Promise<string> {
  const clientDataHash = await sha256(fromBase64Url(clientDataJSON));
  const signatureBase = concat(authData, clientDataHash);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, credentialKeyPair.privateKey, signatureBase));
  return toBase64Url(rawToDerSignature(raw));
}

// --- stages ----------------------------------------------------------------
let timer = performance.now();

if (options.migrateToken || options.adminToken) {
  if (options.migrateToken) {
    const migrate = await fetch(`${baseOrigin}/_internal/migrate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${options.migrateToken}` },
    });
    console.log(`migration: ${migrate.status} ${await migrate.clone().text()}`);
    if (migrate.status !== 200) process.exit(1);
  }
  if (options.adminToken) {
    const bootstrap = await fetch(`${baseOrigin}/api/admin/bootstrap`, {
      method: "POST",
      headers: { Authorization: `Bearer ${options.adminToken}`, "Content-Type": "application/json", "Origin": baseOrigin },
      body: JSON.stringify({ email: options.email, name: options.name, username: options.username, password: options.password }),
    });
    console.log(`bootstrap: ${bootstrap.status} ${await bootstrap.clone().text()}`);
    if (bootstrap.status !== 201 && bootstrap.status !== 409) process.exit(1);
  }
}

const signInStart = performance.now();
const signIn = await call("/api/auth/sign-in/username", {
  method: "POST",
  origin: true,
  body: { username: options.username, password: options.password },
});
const signInBody = await signIn.json().catch(() => ({}));
console.log(`sign-in: ${signIn.status} (${Math.round(performance.now() - timer)} ms)`);
if (signIn.status !== 200) {
  console.log(`unexpected sign-in body: ${JSON.stringify(signInBody)}`);
  process.exit(1);
}

timer = performance.now();
const registerOptions = await call("/api/auth/passkey/generate-register-options");
const registerOptionsJson = await registerOptions.json();
if (registerOptions.status !== 200) {
  console.log(`register options: ${registerOptions.status} ${JSON.stringify(registerOptionsJson)}`);
  process.exit(1);
}
const registrationRpId = registerOptionsJson.rp?.id as string;
const registrationChallenge = registerOptionsJson.challenge as string;
const clientDataCreate = toBase64Url(JSON.stringify({
  type: "webauthn.create",
  challenge: registrationChallenge,
  origin: baseOrigin,
  crossOrigin: false,
}));
const authData = await authenticatorData(registrationRpId, 0x43, true);
const attestationObject = cborEncode(new Map<string, Cbor>([
  ["fmt", "none"],
  ["attStmt", new Map()],
  ["authData", authData],
]));
const registrationResponse = {
  id: toBase64Url(CREDENTIAL_ID),
  rawId: toBase64Url(CREDENTIAL_ID),
  type: "public-key",
  response: {
    clientDataJSON: clientDataCreate,
    attestationObject: toBase64Url(attestationObject),
    transports: ["internal"],
  },
};
const registerVerify = await call("/api/auth/passkey/verify-registration", {
  method: "POST",
  origin: true,
  body: { response: registrationResponse, name: "bench-passkey" },
});
const registerBody = await registerVerify.json().catch(() => ({}));
console.log(`passkey registration: ${registerVerify.status} (${Math.round(performance.now() - timer)} ms)`, registerVerify.status !== 200 ? JSON.stringify(registerBody) : "");
if (registerVerify.status !== 200) process.exit(1);

timer = performance.now();
const authenticateOptions = await call("/api/auth/passkey/generate-authenticate-options");
const authenticateOptionsJson = await authenticateOptions.json();
if (authenticateOptions.status !== 200) {
  console.log(`authentication options: ${authenticateOptions.status} ${JSON.stringify(authenticateOptionsJson)}`);
  process.exit(1);
}
const authenticationChallenge = authenticateOptionsJson.challenge as string;
const allowList = (authenticateOptionsJson.allowCredentials ?? []) as Array<{ id: string }>;
const listedCredential = allowList.find((item) => item.id === toBase64Url(CREDENTIAL_ID));
if (!listedCredential) {
  console.log("the registered credential is not in allowCredentials");
  process.exit(1);
}
const clientDataGet = toBase64Url(JSON.stringify({
  type: "webauthn.get",
  challenge: authenticationChallenge,
  origin: baseOrigin,
  crossOrigin: false,
}));
const assertionAuthData = await authenticatorData(authenticateOptionsJson.rpId ?? registrationRpId, 0x05, false);
const assertion = {
  id: toBase64Url(CREDENTIAL_ID),
  rawId: toBase64Url(CREDENTIAL_ID),
  type: "public-key",
  response: {
    clientDataJSON: clientDataGet,
    authenticatorData: toBase64Url(assertionAuthData),
    signature: await verifySignatureForClientData(assertionAuthData, clientDataGet),
    userHandle: null,
  },
};
const authenticateVerify = await call("/api/auth/passkey/verify-authentication", {
  method: "POST",
  origin: true,
  body: { response: assertion },
});
const authenticateBody = await authenticateVerify.json().catch(() => ({}));
console.log(`passkey authentication: ${authenticateVerify.status} (${Math.round(performance.now() - timer)} ms)`, authenticateVerify.status !== 200 ? JSON.stringify(authenticateBody) : "");
if (authenticateVerify.status !== 200) process.exit(1);
const authenticatedUser = authenticateBody.user?.username ?? authenticateBody.user?.email;
if (authenticatedUser !== options.username) {
  console.log(`authenticated as an unexpected user: ${JSON.stringify(authenticateBody)}`);
  process.exit(1);
}
console.log(`passkey smoke OK on ${baseOrigin}: registered "${authenticatedUser}" and authenticated with a synthetic ES256 credential.`);
