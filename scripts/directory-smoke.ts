/**
 * Operator tooling: exercise the directory group administration API on a
 * running local workerd instance, including the negative and authorization
 * paths. Run with:
 *
 *   bun run scripts/directory-smoke.ts [--migrate-token t] [--admin-token t]
 *
 * Mirrors scripts/passkey-smoke.ts: disposable local database only, throwaway
 * inline credentials, and a fresh D1 database is expected for the bootstrap
 * stage.
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
function cookieHeader(): string {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}
async function call(path: string, init?: { method?: "GET" | "POST" | "DELETE"; body?: unknown; origin?: boolean; cookies?: boolean }): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init?.cookies !== false && cookieHeader()) headers.Cookie = cookieHeader();
  if (init?.origin) headers.Origin = base;
  if (init?.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${base}${path}`, {
    method: init?.method ?? "GET",
    headers,
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });
  absorb(response);
  return response;
}

function toHex8(): string {
  const raw = new Uint8Array(4);
  crypto.getRandomValues(raw);
  return Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
}

function expect(step: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`PASS ${step}`);
    return;
  }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 300));
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
  const status = await bootstrap.text();
  expect("bootstrap", bootstrap.status === 201 || bootstrap.status === 409, status);
}

const signIn = await call("/api/auth/sign-in/username", { method: "POST", origin: true, body: { username: options.username, password: options.password } });
expect("admin sign-in", signIn.status === 200, await signIn.clone().text());
const sessionJson = await signIn.json();
const adminUserId = (sessionJson as { user?: { id?: string } }).user?.id ?? "";
expect("admin user id present", adminUserId.length > 0);
let adminUserReference = adminUserId;
const groupName = `engineering-${toHex8()}`;

// Without an origin header an authenticated mutation must be rejected.
const noOrigin = await call("/api/admin/directory-groups", { method: "POST", body: { name: "no-origin" }, origin: false });
expect("originless mutation rejected", noOrigin.status === 403, noOrigin.status);
// Without a session the read must be rejected.
const anonymous = await fetch(`${base}/api/admin/directory-groups`);
expect("anonymous read rejected", anonymous.status === 401, anonymous.status);

const created = await call("/api/admin/directory-groups", { method: "POST", origin: true, body: { name: groupName, description: "Smoke group" } });
expect("group created", created.status === 201, await created.clone().text());
const createdBody = (await created.json()) as { group?: { id?: string; createdBy?: string } };
const groupId = createdBody.group?.id ?? "";
expect("group id returned", groupId.length > 0, createdBody);
expect("createdBy is the acting admin", createdBody.group?.createdBy === adminUserId, createdBody);

const duplicate = await call("/api/admin/directory-groups", { method: "POST", origin: true, body: { name: groupName } });
expect("duplicate name rejected", duplicate.status === 409, duplicate.status);

const invalidName = await call("/api/admin/directory-groups", { method: "POST", origin: true, body: { name: "not allowed/bad" } });
expect("invalid name rejected", invalidName.status === 400, invalidName.status);

const addSelf = await call(`/api/admin/directory-groups/${groupId}/members`, { method: "POST", origin: true, body: { userId: adminUserId } });
expect("member added", addSelf.status === 201, { status: addSelf.status, group: groupId, body: await addSelf.clone().text() });
const again = await call(`/api/admin/directory-groups/${groupId}/members`, { method: "POST", origin: true, body: { userId: adminUserId } });
expect("duplicate member rejected", again.status === 409, again.status);
const unknownUser = await call(`/api/admin/directory-groups/${groupId}/members`, { method: "POST", origin: true, body: { userId: "does-not-exist" } });
expect("unknown user rejected", unknownUser.status === 404, unknownUser.status);

const detail = await call(`/api/admin/directory-groups/${groupId}`);
const detailJson = await detail.json() as { members?: Array<{ userId: string }>; group?: { name?: string } };
expect("detail lists the member", detail.status === 200 && detailJson.members?.some((m) => m.userId === adminUserId) === true, detailJson);
expect("detail has the group name", detailJson.group?.name === groupName);

const list = await call("/api/admin/directory-groups");
const listJson = await list.json() as { groups?: Array<{ name?: string }> };
expect("list includes the group", list.status === 200 && listJson.groups?.some((g) => g.name === groupName) === true, listJson);

const removedMember = await call(`/api/admin/directory-groups/${groupId}/members/${adminUserId}`, { method: "DELETE", origin: true });
expect("member removed", removedMember.status === 200, await removedMember.clone().text());
const removeAgain = await call(`/api/admin/directory-groups/${groupId}/members/${adminUserId}`, { method: "DELETE", origin: true });
expect("removing absent membership rejected", removeAgain.status === 404, removeAgain.status);

const deleted = await call(`/api/admin/directory-groups/${groupId}`, { method: "DELETE", origin: true });
expect("group deleted", deleted.status === 200, await deleted.clone().text());
const deleteAgain = await call(`/api/admin/directory-groups/${groupId}`, { method: "DELETE", origin: true });
expect("deleting absent group rejected", deleteAgain.status === 404, deleteAgain.status);

const auditList = await call("/api/admin/audit-events?limit=50");
const auditJson = await auditList.json().catch(() => null) as { events?: Array<{ event_type?: string }> } | null;
const types = JSON.stringify(auditJson?.events?.map((event) => event.event_type) ?? []);
expect("audited mutations appear in the D1 audit API", auditList.status === 200 && types.includes("directory.group.create") && types.includes("directory.member.remove"), types.slice(0, 300));

console.log("directory smoke OK: groups and memberships behave behind the admin gate with audit events.");
