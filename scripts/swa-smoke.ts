/**
 * Operator tooling: exercise the SWA workflow end to end on a running local
 * workerd instance, including the authorization gates, single-use consumption
 * and the visible-grants view.
 *
 *   bun run scripts/swa-smoke.ts [--migrate-token t] [--admin-token t]
 *
 * Disposable local database and throwaway inline credentials only.
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
function readOption(key: string): string | null {
  const index = rawArgs.indexOf(`--${key}`);
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
const base = new URL(options.base).origin;

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
async function call(path: string, init?: { method?: "GET" | "POST" | "DELETE"; body?: unknown; origin?: boolean; headers?: Record<string, string> }): Promise<Response> {
  const headers: Record<string, string> = { ...(init?.headers ?? {}) };
  if (cookiePair()) headers.Cookie = cookiePair();
  if (init?.origin) headers.Origin = base;
  if (init?.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${base}${path}`, { method: init?.method ?? "GET", headers, body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
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

if (options.migrateToken) {
  const migrate = await fetch(`${base}/_internal/migrate`, { method: "POST", headers: { Authorization: `Bearer ${options.migrateToken}` } });
  expect("migration", migrate.status === 200, await migrate.clone().text());
}
if (options.adminToken) {
  const bootstrap = await fetch(`${base}/api/admin/bootstrap`, {
    method: "POST",
    headers: { Authorization: `Bearer ${options.adminToken}`, "Content-Type": "application/json", "Origin": base },
    body: JSON.stringify({ email: options.email, name: options.name, username: options.username, password: options.password }),
  });
  expect("bootstrap", [201, 409].includes(bootstrap.status), await bootstrap.clone().text());
}
const signIn = await call("/api/auth/sign-in/username", { method: "POST", origin: true, body: { username: options.username, password: options.password } });
expect("sign-in", signIn.status === 200, signIn.status);

// Register and enable an SWA application.
const origin = `https://swa-app-${crypto.randomUUID().slice(0, 8)}.test`;
const register = await call("/api/admin/swa-applications", { method: "POST", origin: true, body: { name: `swa-smoke-${crypto.randomUUID().slice(0, 6)}`, origin } });
const registerBody = await register.json().catch(() => ({})) as { application?: { id?: string } };
expect("application registered disabled", register.status === 201, { status: register.status, body: registerBody });
const applicationId = registerBody.application?.id ?? "";
await call(`/api/admin/swa-applications/${applicationId}/enable`, { method: "POST", origin: true });

// Before enablement... grants for an unregistered origin reject.
const stranger = await call("/api/swa/grants", { method: "POST", origin: true, body: { origin: "https://unregistered-swa.test" } });
expect("unregistered origin rejected", stranger.status === 401, stranger.status);

// A disabled application rejects grants.
const disabled = await call(`/api/admin/swa-applications/${applicationId}/disable`, { method: "POST", origin: true });
expect("application disabled", disabled.status === 200, disabled.status);
const beforeEnable = await call("/api/swa/grants", { method: "POST", origin: true, body: { origin } });
expect("disabled application rejects grants", beforeEnable.status === 401, beforeEnable.status);
await call(`/api/admin/swa-applications/${applicationId}/enable`, { method: "POST", origin: true });

// A group-gated policy in enforce mode blocks grant issuance for users outside
// the configured groups; removal restores issuance. Policy groups reference
// real directory groups, so create one the acting user is NOT enrolled in.
const policySubject = `swa:${origin}`;
const gateGroup = await call("/api/admin/directory-groups", {
  method: "POST",
  origin: true,
  body: { name: `swa-gate-${crypto.randomUUID().slice(0, 8)}` },
});
const gateGroupBody = await gateGroup.json().catch(() => ({})) as { group?: { id?: string } };
expect("gate directory group created", gateGroup.status === 201 && !!gateGroupBody.group?.id, { status: gateGroup.status, body: gateGroupBody });
const policyPut = await call("/api/admin/app-access-policies", {
  method: "PUT",
  origin: true,
  body: { subject: policySubject, enforcementMode: "enforce", groups: [gateGroupBody.group?.id ?? ""] },
});
expect("group-gated policy stored", policyPut.status === 200, policyPut.status);
const gateBlocked = await call("/api/swa/grants", { method: "POST", origin: true, body: { origin } });
expect("group gate violation rejected (403)", gateBlocked.status === 403, gateBlocked.status);
const policyDelete = await call(`/api/admin/app-access-policies/${encodeURIComponent(policySubject)}`, { method: "DELETE", origin: true });
expect("policy removed", policyDelete.status === 200 || policyDelete.status === 204, policyDelete.status);
const gateGroupDelete = await call(`/api/admin/directory-groups/${gateGroupBody.group?.id ?? ""}`, { method: "DELETE", origin: true });
expect("gate directory group removed", gateGroupDelete.status === 200 || gateGroupDelete.status === 204, gateGroupDelete.status);

// Grant issuance for the acting user.
const grant = await call("/api/swa/grants", { method: "POST", origin: true, body: { origin } });
const grantBody = await grant.json().catch(() => ({})) as { nonce?: string; expiresAt?: string };
expect("grant issued", grant.status === 201 && !!grantBody.nonce, { status: grant.status, body: grantBody });

// Grant exchange: proves possession of the nonce within the same session.
const exchange = await call("/api/swa/exchange", { method: "POST", origin: true, body: { nonce: grantBody.nonce } });
const exchangeBody = await exchange.json().catch(() => ({})) as { attestation?: { application?: { origin?: string }; userId?: string } };
expect("grant exchanged", exchange.status === 200 && exchangeBody.attestation?.application?.origin === origin, { status: exchange.status, body: exchangeBody });

// The consumed nonce is single-use: a replay rejects.
const replay = await call("/api/swa/exchange", { method: "POST", origin: true, body: { nonce: grantBody.nonce } });
expect("replayed nonce rejected", replay.status === 401, replay.status);

// Grants are session-bound: a foreign (unauthenticated) client cannot mint one.
const grantUnauthed = await fetch(`${base}/api/swa/grants`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Origin": base },
  body: JSON.stringify({ origin }),
});
expect("unauthenticated grant request rejected", grantUnauthed.status === 401, grantUnauthed.status);
const grantAgain = await call("/api/swa/grants", { method: "POST", origin: true, body: { origin } });
const grantAgainBody = await grantAgain.json().catch(() => ({})) as { nonce?: string };
expect("second grant issued for the same user", grantAgain.status === 201 && !!grantAgainBody.nonce, grantAgain.status);

// The grants view is visible and nonce-masked.
const listed = await call(`/api/admin/swa-applications/${applicationId}/grants`);
const listedBody = await listed.json().catch(() => ({})) as { grants?: Array<{ nonce?: string; consumed?: boolean }> };
expect(
  "grants view visible with masked nonces",
  listed.status === 200 && listedBody.grants?.length >= 2 && (listedBody.grants?.[0]?.nonce ?? "").includes("…") === true,
  listedBody,
);

// Deletion of an application kills new grants.
await call(`/api/admin/swa-applications/${applicationId}/disable`, { method: "POST", origin: true });
await call(`/api/admin/swa-applications/${applicationId}`, { method: "DELETE", origin: true });
const afterDelete = await call("/api/swa/grants", { method: "POST", origin: true, body: { origin } });
expect("deleted application rejects grants", afterDelete.status === 401, afterDelete.status);

// The mutations are audited with actor and application targets.
const auditList = await call("/api/admin/audit-events?limit=100");
const auditJson = await auditList.json().catch(() => null) as { events?: Array<{ event_type?: string; target_user_id?: string }> } | null;
const issued = auditJson?.events?.find((event) => event.event_type === "swa.grant.issue");
expect(
  "grant mutations audited",
  issued !== undefined && issued.target_user_id === applicationId,
  issued ?? "no event",
);

console.log("swa smoke OK: registration lifecycle, user grants, single-use exchange, masked activity view and audit.");
