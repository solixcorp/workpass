/**
 * Operator tooling: verify the RFC 8693 token exchange against a running
 * local worker (ENABLE_TOKEN_EXCHANGE=true) end to end — operator-provisioned
 * confidential client, authorization-code subject token with a long-TTL
 * resource, exchange onto a shorter-TTL delegated resource, scope narrowing,
 * lifetime non-extension, and representative failure paths.
 *
 * Setup expectations (see docs/operations/production-checklist.md):
 *   ENABLE_MIGRATIONS=true  MIGRATION_TOKEN=...
 *   ENABLE_ADMIN_BOOTSTRAP=true  ADMIN_BOOTSTRAP_TOKEN=...
 *   ENABLE_DYNAMIC_CLIENT_REGISTRATION=true  CLIENT_REGISTRATION_TOKEN=...
 *   ENABLE_TOKEN_EXCHANGE=true
 *   TOKEN_EXCHANGE_ALLOWED_RESOURCES={"exchange-client":["https://api.pay.test/delegated"]}
 *   OAUTH_RESOURCES=[{"identifier":"https://api.pay.test/","accessTokenTtl":600},
 *                    {"identifier":"https://api.pay.test/delegated","accessTokenTtl":300}]
 *
 *   bun run scripts/token-exchange-smoke.ts [--admin-token t] [--migrate-token t] [--dcr-token t]
 *
 * Disposable local database and throwaway inline credentials only.
 */

const base = new URL(readOption("base") ?? "http://127.0.0.1:8787").origin;

function readOption(key: string): string | null {
  const index = Bun.argv.indexOf(`--${key}`);
  return index >= 0 && index + 1 < Bun.argv.length ? Bun.argv[index + 1]! : null;
}

function expect(step: string, condition: boolean, detail?: unknown): void {
  if (condition) { console.log(`PASS ${step}`); return; }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 300));
  process.exit(1);
}
function b64u(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}
function jwtParts(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const pieces = jwt.split(".");
  expect("subject JWT shape", pieces.length === 3, pieces.length);
  return {
    header: JSON.parse(new TextDecoder().decode(b64u(pieces[0]!))) as Record<string, unknown>,
    payload: JSON.parse(new TextDecoder().decode(b64u(pieces[1]!))) as Record<string, unknown>,
  };
}

const RESOURCE_PRIMARY = "https://api.pay.test/";
const RESOURCE_DELEGATED = "https://api.pay.test/delegated";
const RP_CALLBACK = "https://rp.exchange-smoke.test/cb";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

// Skip (exit 0) on deployments that have not opted in; the smoke runner must
// not fail for features that are disabled by configuration.
const metadata = await fetch(`${base}/api/auth/.well-known/oauth-authorization-server/api/auth`);
const metadataBody = await metadata.json() as { grant_types_supported?: string[] };
if (!(metadataBody.grant_types_supported ?? []).includes(EXCHANGE_GRANT)) {
  console.log("SKIP token-exchange smoke: the worker does not advertise the token-exchange grant");
  process.exit(0);
}

const jar = new Map<string, string>();
function absorb(response: Response): void {
  for (const header of response.headers.getSetCookie()) {
    const pair = header.split(";")[0]!;
    const separator = pair.indexOf("=");
    if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}
function cookiePair(): string {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}
async function call(path: string, init?: { method?: "GET" | "POST"; body?: unknown; headers?: Record<string, string>; form?: string }): Promise<Response> {
  const headers: Record<string, string> = { ...(init?.headers ?? {}) };
  if (cookiePair()) headers.Cookie = cookiePair();
  if (init?.body !== undefined) headers["Content-Type"] = "application/json";
  if (init?.form !== undefined) { headers["Content-Type"] = "application/x-www-form-urlencoded"; headers.Origin = base; }
  return fetch(`${base}${path}`, {
    method: init?.method ?? "GET", headers, redirect: "manual",
    body: init?.form ?? (init?.body === undefined ? undefined : JSON.stringify(init.body)),
  }).then((response) => { absorb(response); return response; });
}

const migrateToken = readOption("migrate-token");
if (migrateToken) {
  const migrate = await fetch(`${base}/_internal/migrate`, { method: "POST", headers: { Authorization: `Bearer ${migrateToken}` } });
  expect("migration", migrate.status === 200, await migrate.clone().text());
}
const adminToken = readOption("admin-token");
if (adminToken) {
  const username = `tx-smoke-${crypto.randomUUID().slice(0, 8)}`;
  const password = "SmokeOnly-7d9Kpw9zL2";
  const bootstrap = await call("/api/admin/bootstrap", {
    method: "POST", headers: { Authorization: `Bearer ${adminToken}` },
    body: { email: `${username}@example.com`, name: "Token Exchange Smoke", username, password },
  });
  expect("bootstrap", [201, 409].includes(bootstrap.status), await bootstrap.clone().text());
  const signIn = await call("/api/auth/sign-in/username", { method: "POST", body: { username, password } });
  expect("sign-in", signIn.status === 200, signIn.status);
}

const dcrToken = readOption("dcr-token") ?? "operator-provisioned-dcr-token-0123456789abcdef";
const register = await call("/api/auth/oauth2/register", {
  method: "POST", headers: { Authorization: `Bearer ${dcrToken}` },
  body: {
    client_name: "token-exchange-smoke",
    redirect_uris: [RP_CALLBACK],
    token_endpoint_auth_method: "client_secret_basic",
    grant_types: ["authorization_code", EXCHANGE_GRANT],
    response_types: ["code"],
    scope: "openid profile email",
    resources: [RESOURCE_PRIMARY, RESOURCE_DELEGATED],
  },
});
const registered = await register.json() as { client_id?: string; client_secret?: string };
expect("confidential client registered", register.status === 201 && !!registered.client_id && !!registered.client_secret, register.status);
const clientId = registered.client_id ?? "";
const clientSecret = registered.client_secret ?? "";
const basic = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;

const verifierWords = new Uint8Array(32);
crypto.getRandomValues(verifierWords);
const verifier = btoa(String.fromCharCode(...verifierWords)).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const challenge = btoa(String.fromCharCode(...new Uint8Array(
  await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
))).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const authorize = await call(`/api/auth/oauth2/authorize?${new URLSearchParams({
  client_id: clientId, redirect_uri: RP_CALLBACK, response_type: "code", scope: "profile email",
  state: "tx-smoke", code_challenge: challenge, code_challenge_method: "S256", resource: RESOURCE_PRIMARY,
})}`);
const consentLocation = authorize.headers.get("location") ?? "";
expect("authorize continues past policy", authorize.status === 302 && consentLocation.includes("/consent?"), { status: authorize.status, location: consentLocation.slice(0, 120) });
const consentUrl = consentLocation.startsWith("/") ? `${base}${consentLocation}` : consentLocation;
const consentPage = await call(consentUrl);
expect("consent page renders", consentPage.status === 200, consentPage.status);
const consent = await call("/api/auth/oauth2/consent", {
  method: "POST",
  body: { oauth_query: new URL(consentUrl).search.slice(1), accept: true, scopes: ["profile", "email"] },
});
const consentJson = await consent.json() as { redirectURI?: string; url?: string };
const redirect = consentJson.url ?? consentJson.redirectURI ?? "";
const code = new URL(redirect).searchParams.get("code") ?? "";
expect("consent approved with a code", consent.status === 200 && code.length > 0, { status: consent.status, redirect });

const mint = await call("/api/auth/oauth2/token", {
  method: "POST", form: new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri: RP_CALLBACK, code_verifier: verifier,
  }).toString(), headers: { Authorization: basic },
});
const minted = await mint.json() as { access_token?: string };
expect("authorization-code mint", mint.status === 200 && !!minted.access_token, mint.status);
const subjectToken = minted.access_token ?? "";
const subject = jwtParts(subjectToken);
expect("subject is an RFC 9068 access-token JWT bound to the primary resource",
  subject.header.typ === "at+jwt" && subject.payload.aud === RESOURCE_PRIMARY && typeof subject.payload.sid === "string",
  subject.header.typ);

// Happy path: exchange onto the shorter-TTL delegated resource with a narrowed scope.
const exchange = await call("/api/auth/oauth2/token", {
  method: "POST", form: new URLSearchParams({
    grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
    resource: RESOURCE_DELEGATED, scope: "profile",
  }).toString(), headers: { Authorization: basic },
});
const exchanged = await exchange.json() as { access_token?: string; issued_token_type?: string; expires_in?: number };
expect("exchange mints a delegation token", exchange.status === 200 && !!exchanged.access_token, { status: exchange.status, body: exchanged });
const output = jwtParts(exchanged.access_token ?? "");
expect("delegation shape (RFC 8693)",
  exchanged.issued_token_type === ACCESS_TOKEN_TYPE && output.header.typ === "at+jwt" &&
  output.payload.aud === RESOURCE_DELEGATED && output.payload.scope === "profile",
  exchanged);
expect("delegation never outlives the subject", Number(output.payload.exp) < Number(subject.payload.exp),
  { sub: subject.payload.exp, out: output.payload.exp, expires_in: exchanged.expires_in });

// Failure paths.
const badTarget = await call("/api/auth/oauth2/token", {
  method: "POST", form: new URLSearchParams({
    grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
    resource: "https://not-approved.test/",
  }).toString(), headers: { Authorization: basic },
});
expect("unallowlisted target rejected", badTarget.status === 400, badTarget.status);
const sameResource = await call("/api/auth/oauth2/token", {
  method: "POST", form: new URLSearchParams({
    grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
    resource: RESOURCE_PRIMARY,
  }).toString(), headers: { Authorization: basic },
});
expect("target whose TTL exceeds the subject remaining life is rejected", sameResource.status === 400, sameResource.status);
const escalate = await call("/api/auth/oauth2/token", {
  method: "POST", form: new URLSearchParams({
    grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
    resource: RESOURCE_DELEGATED, scope: "profile email admin",
  }).toString(), headers: { Authorization: basic },
});
expect("scope escalation rejected", escalate.status === 400, escalate.status);
const actor = await call("/api/auth/oauth2/token", {
  method: "POST", form: new URLSearchParams({
    grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
    resource: RESOURCE_DELEGATED, actor_token: "unsupported",
  }).toString(), headers: { Authorization: basic },
});
expect("actor_token (delegation chains) rejected in this profile", actor.status === 400, actor.status);
const wrongSecret = await call("/api/auth/oauth2/token", {
  method: "POST", form: new URLSearchParams({
    grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
    resource: RESOURCE_DELEGATED,
  }).toString(), headers: { Authorization: `Basic ${btoa(`${clientId}:wrong`)}` },
});
expect("wrong client secret rejected", wrongSecret.status === 401 || wrongSecret.status === 400, wrongSecret.status);

console.log("token-exchange smoke OK: allowed exchange mints a narrowed, shorter-lived, properly audited delegation; failure paths reject.");
