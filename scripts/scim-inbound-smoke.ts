/**
 * Operator tooling: verify the inbound SCIM 2.0 server end to end against a
 * running local worker — no HR system required. Bearer-token auth (positive
 * and negative), user creation without credentials, duplicate rejection,
 * filtering, deactivation/activation, and delete-as-deactivate.
 *
 *   bun run scripts/scim-inbound-smoke.ts --token <t>  # token comes from INBOUND_SCIM_BEARER_TOKEN
 */

const rawArgs = Bun.argv.slice(2);
async function readDevVarsToken(): Promise<string> {
  try {
    const { readFileSync } = await import("node:fs");
    const line = readFileSync(".dev.vars", "utf8")
      .split("\n").find((l) => l.startsWith("INBOUND_SCIM_BEARER_TOKEN="));
    return (line ?? "").split("=").slice(1).join("=").trim().replace(/^"|"$/g, "");
  } catch {
    return "";
  }
}
function readOption(key: string): string | null {
  const index = rawArgs.indexOf(`--${key}`);
  return index >= 0 && rawArgs[index + 1] ? rawArgs[index + 1]! : null;
}

const options = {
  base: readOption("base") ?? "http://127.0.0.1:8787",
  token: readOption("token") ?? await readDevVarsToken(),
};

const base = options.base;

function expect(step: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`PASS ${step}`);
    return;
  }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 400));
  process.exit(1);
}

const scimHeaders = (token: string): Record<string, string> => ({
  Authorization: `Bearer ${token}`,
  "Content-Type": "application/scim+json",
});

const suffix = crypto.randomUUID().slice(0, 8);
const provisionEmail = `scim-inbound-${suffix}@example.com`;

const config = await fetch(`${base}/scim/v2/ServiceProviderConfig`);
expect("service provider config", config.status === 200);

const unauthenticated = await fetch(`${base}/scim/v2/Users`);
expect("unauthenticated rejected", unauthenticated.status === 401, unauthenticated.status);

const wrongToken = await fetch(`${base}/scim/v2/Users`, { headers: { Authorization: "Bearer wrong-token-000000000000000000000" } });
expect("wrong token rejected", wrongToken.status === 401, wrongToken.status);

const create = await fetch(`${base}/scim/v2/Users`, {
  method: "POST",
  headers: scimHeaders(options.token),
  body: JSON.stringify({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: provisionEmail,
    name: { formatted: "SCIM Provisioned" },
    emails: [{ value: provisionEmail, primary: true }],
  }),
});
const createBody = await create.json().catch(() => ({})) as { id?: string; active?: boolean };
expect("user provisioned", create.status === 201 && !!createBody.id, { status: create.status, body: createBody });
const userId = createBody.id ?? "";

const duplicate = await fetch(`${base}/scim/v2/Users`, {
  method: "POST",
  headers: scimHeaders(options.token),
  body: JSON.stringify({ userName: provisionEmail, name: { formatted: "Duplicate" } }),
});
expect("duplicate email rejected", duplicate.status === 409, duplicate.status);

const fetched = await fetch(`${base}/scim/v2/Users/${userId}`, { headers: scimHeaders(options.token) });
const fetchedBody = await fetched.json().catch(() => ({})) as { id?: string; active?: boolean };
expect("user fetched by id", fetched.status === 200 && fetchedBody.id === userId, fetched.status);

const filtered = await fetch(`${base}/scim/v2/Users?filter=userName eq "${provisionEmail}"`, { headers: scimHeaders(options.token) });
const filteredBody = await filtered.json().catch(() => ({})) as { Resources?: Array<{ userName?: string }> };
expect("user filterable", filtered.status === 200 && filteredBody.Resources?.[0]?.userName === provisionEmail, filtered.status);

const updated = await fetch(`${base}/scim/v2/Users/${userId}`, {
  method: "PUT",
  headers: scimHeaders(options.token),
  body: JSON.stringify({
    userName: provisionEmail,
    name: { formatted: "SCIM Provisioned II" },
    active: true,
  }),
});
const updatedBody = await updated.json().catch(() => ({})) as { name?: { formatted?: string } };
expect("user updated via PUT", updated.status === 200 && updatedBody.name?.formatted === "SCIM Provisioned II", updatedBody);

const deactivated = await fetch(`${base}/scim/v2/Users/${userId}`, {
  method: "PATCH",
  headers: scimHeaders(options.token),
  body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", path: "active", value: false }] }),
});
const deactivatedBody = await deactivated.json().catch(() => ({})) as { active?: boolean };
expect("user deactivated via PATCH", deactivated.status === 200 && deactivatedBody.active === false, deactivatedBody);

const reactivate = await fetch(`${base}/scim/v2/Users/${userId}`, {
  method: "PATCH",
  headers: scimHeaders(options.token),
  body: JSON.stringify({ Operations: [{ op: "replace", path: "active", value: true }] }),
});
const reactivateBody = await reactivate.json().catch(() => ({})) as { active?: boolean };
expect("user reactivated", reactivate.status === 200 && reactivateBody.active === true, reactivateBody);

const removed = await fetch(`${base}/scim/v2/Users/${userId}`, { method: "DELETE", headers: scimHeaders(options.token) });
expect("delete accepted (deactivates)", removed.status === 204, removed.status);

const afterDelete = await fetch(`${base}/scim/v2/Users/${userId}`, { headers: scimHeaders(options.token) });
const afterDeleteBody = await afterDelete.json().catch(() => ({})) as { active?: boolean };
expect("delete deactivates, does not destroy", afterDelete.status === 200 && afterDeleteBody.active === false, afterDeleteBody);

console.log("inbound SCIM smoke OK: bearer auth, provisioning without credentials, duplicates, filtering, updates, deactivation semantics.");
