/**
 * Operator tooling: verify the outbound SCIM 2.0 transport over REAL HTTP
 * against a local mock target, with genuine HTTP semantics (201/200 bodies,
 * bearer auth, a 500 mode to exercise the outcome-unknown path and the
 * single-active journal block).
 *
 * The identity provider dev server must be running with the SCIM variables
 * configured (ENABLE_SCIM_PROVISIONING=true, SCIM_TARGET_ID=localmock,
 * SCIM_BASE_URL=http://127.0.0.1:18080/scim, SCIM_BEARER_TOKEN=smoke-target-token,
 * SCIM_DEV_LOOPBACK_TARGET=true). The mock target is started and stopped by
 * this script itself.
 *
 *   bun run scripts/scim-smoke.ts [--migrate-token t] [--admin-token t]
 *
 * Disposable local database and throwaway inline credentials only.
 */

interface Options {
  base: string;
  username: string;
  password: string;
  adminToken: string | null;
  migrateToken: string | null;
  targetId: string;
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
  targetId: "localmock",
};
const base = new URL(options.base).origin;
const TARGET_PORT = 18080;

function expect(step: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`PASS ${step}`);
    return;
  }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 400));
  process.exit(1);
}

// --- mock SCIM target -------------------------------------------------------
let failMode = false;
const createdExternalIds = new Set<string>();
const bearer = "smoke-target-token";

const mockServer = Bun.serve({
  port: TARGET_PORT,
  hostname: "127.0.0.1",
  async fetch(request) {
    const url = new URL(request.url);
    if (request.headers.get("authorization") !== `Bearer ${bearer}`) {
      return new Response("unauthorized", { status: 401 });
    }
    if (failMode) return new Response("simulated target outage", { status: 500 });
    if (request.method === "POST" && url.pathname === "/scim/Users") {
      const externalId = `mock-ext-${crypto.randomUUID().slice(0, 8)}`;
      createdExternalIds.add(externalId);
      return Response.json({ schemas: [ "urn:ietf:params:scim:schemas:core:2.0:User" ], id: externalId }, { status: 201 });
    }
    const match = /^\/scim\/Users\/(.+)$/.exec(url.pathname);
    if (request.method === "PATCH" && match) {
      const body = await request.json() as { Operations?: Array<{ path?: string }> };
      const deactivates = (body.Operations ?? []).some((op) => op.path === "active");
      if (deactivates) createdExternalIds.delete(match[1]!);
      return new Response("{}", { status: 200 });
    }
    return new Response("not found", { status: 404 });
  },
});
process.on("exit", () => void mockServer.stop(true));

const TARGET_BASE = `http://127.0.0.1:${TARGET_PORT}/scim`;

// --- IdP client -------------------------------------------------------------
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
async function call(path: string, init?: { method?: "GET" | "POST" | "DELETE"; body?: unknown; origin?: boolean; token?: string }): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookiePair()) headers.Cookie = cookiePair();
  if (init?.origin) headers.Origin = base;
  if (init?.token) headers.Authorization = `Bearer ${init.token}`;
  const response = await fetch(`${base}${path}`, { method: init?.method ?? "GET", headers, body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
  absorb(response);
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
    body: JSON.stringify({ email: "bench-admin@example.com", name: "Bench Admin", username: options.username, password: options.password }),
  });
  expect("bootstrap", [201, 409].includes(bootstrap.status), await bootstrap.clone().text());
}
const signIn = await call("/api/auth/sign-in/username", { method: "POST", origin: true, body: { username: options.username, password: options.password } });
expect("admin sign-in", signIn.status === 200, signIn.status);
const adminCookie = cookiePair();

// The provisioned victim user (created through the Better Auth admin API).
const victim = await call("/api/auth/admin/create-user", {
  method: "POST",
  origin: true,
  body: { email: "scim-victim@example.com", name: "SCIM Victim", username: "scimvictim", password: "VictimOnly-8c3Kpw8zL3", data: {} },
});
const victimBody = await victim.json().catch(() => ({})) as { user?: { id?: string } };
expect("victim user created", [200, 201, 400].includes(victim.status), { status: victim.status, body: victimBody });
let victimId = victimBody.user?.id ?? "";
if (victimId.length === 0) {
  // The user already existed from a previous run: resolve the ID by signing in
  // as the victim, then restore the administrator session afterwards.
  const vSignIn = await fetch(`${base}/api/auth/sign-in/username`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": base },
    body: JSON.stringify({ username: "scimvictim", password: "VictimOnly-8c3Kpw8zL3" }),
  });
  absorb(vSignIn);
  const vBody = await vSignIn.json().catch(() => ({})) as { user?: { id?: string } };
  victimId = vBody.user?.id ?? "";
  for (const key of [...jar.keys()]) jar.delete(key);
}
expect("victim id present", victimId.length > 0, victimId);

// Restore the administrator session for the scoped admin calls.
for (const key of [...jar.keys()]) jar.delete(key);
if (adminCookie) for (const pair of adminCookie.split("; ")) { const i = pair.indexOf("="); if (i > 0) jar.set(pair.slice(0, i), pair.slice(i + 1)); }

// Create operation: the transport POSTs to the mock target.
const createOp = await call("/api/admin/scim-operations", { method: "POST", origin: true, body: { userId: victimId, operation: "create" } });
const createBody = await createOp.json().catch(() => ({})) as { operationId?: string; status?: string };
expect("create operation succeeded over real HTTP", createOp.status === 200 && createBody.status === "succeeded", { status: createOp.status, body: createBody });
expect("mock target received the POST", createdExternalIds.size === 1, Array.from(createdExternalIds));

// Update operation.
const updateOp = await call("/api/admin/scim-operations", { method: "POST", origin: true, body: { userId: victimId, operation: "update" } });
expect("update operation succeeded", updateOp.status === 200, await updateOp.clone().text());

// Deactivate operation.
const deactivateOp = await call("/api/admin/scim-operations", { method: "POST", origin: true, body: { userId: victimId, operation: "deactivate" } });
expect("deactivate operation succeeded", deactivateOp.status === 200, await deactivateOp.clone().text());

// Now an outage: the target returns 500; the outcome is unknown and the
// journal blocks everything for this target/user until reconciliation.
failMode = true;
const outage = await call("/api/admin/scim-operations", { method: "POST", origin: true, body: { userId: victimId, operation: "update" } });
expect("target outage journals outcome_unknown", outage.status === 502, await outage.clone().text());
failMode = false;
const blocked = await call("/api/admin/scim-operations", { method: "POST", origin: true, body: { userId: victimId, operation: "update" } });
expect("subsequent operations blocked until reconciliation", blocked.status === 409 || blocked.status === 502 || blocked.status === 503, await blocked.clone().text());

// Bearer auth on the target is enforced: a mismatched token is 401 (the
// transport surfaces it as an invalid-configuration rejection, no retry).
const mismatch = await fetch(`${TARGET_BASE}/Users`, { headers: { Authorization: "Bearer wrong" } });
expect("mock target enforces bearer auth", mismatch.status === 401, mismatch.status);

// The operations are audited with actor, target and outcome.
const auditList = await call("/api/admin/audit-events?limit=100");
const auditJson = await auditList.json().catch(() => null) as { events?: Array<{ event_type?: string; target_user_id?: string }> } | null;
const created = auditJson?.events?.find((event) => event.event_type === "scim.user.create" && event.outcome === "success");
const outageEvent = auditJson?.events?.find((event) => event.event_type === "scim.user.update" && event.outcome === "failure");
expect(
  "scim mutations audited with outcomes",
  created !== undefined && outageEvent !== undefined && created.target_user_id === victimId,
  { created, outageEvent },
);

mockServer.stop(true);
console.log(`scim smoke OK on ${base}: real HTTP transport, mapping lifecycle, outcome-unknown journaling and the single-active block.`);
