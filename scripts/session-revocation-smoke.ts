/**
 * Operator tooling: verify that IdP-side session revocation propagates
 * immediately through the D1-backed session store on a running local workerd
 * instance. Signs in twice, revokes the user's sessions through the Better
 * Auth administration API, and checks that both cookies stop authorizing
 * while a fresh sign-in still works.
 *
 *   bun run scripts/session-revocation-smoke.ts [--migrate-token t] [--admin-token t]
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
  expect("bootstrap", [201, 409].includes(bootstrap.status), await bootstrap.clone().text());
}

const jarA = new Map<string, string>();
const jarB = new Map<string, string>();
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

for (const [jar, tag] of [[jarA, "A"], [jarB, "B"]] as const) {
  const signIn = await fetch(`${base}/api/auth/sign-in/username`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": base },
    body: JSON.stringify({ username: options.username, password: options.password }),
  });
  absorb(jar, signIn);
  expect(`sign-in ${tag} creates a session`, signIn.status === 200, signIn.status);
}

/** get-session answers 200 with a null body when unauthenticated. */
async function authorizedSessionCheck(jar: Map<string, string>): Promise<boolean> {
  const get = await fetch(`${base}/api/auth/get-session`, { headers: { Cookie: cookiePair(jar) } });
  if (get.status !== 200) return false;
  const body = await get.json().catch(() => null) as { session?: unknown; user?: unknown } | null;
  return Boolean(body && (body.session || body.user));
}

expect("session A authorizes", await authorizedSessionCheck(jarA));
expect("session B authorizes", await authorizedSessionCheck(jarB));

let userIdToRevoke: string | null = null;
for (const jar of [jarA, jarB]) {
  const probe = await fetch(`${base}/api/auth/get-session`, { headers: { Cookie: cookiePair(jar) } });
  if (probe.status === 200) {
    const body = await probe.json() as { user?: { id?: string } };
    userIdToRevoke = body.user?.id ?? null;
    break;
  }
}
expect("a user id is available for revocation", userIdToRevoke !== null);

const revoke = await fetch(`${base}/api/auth/admin/revoke-user-sessions`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Origin": base, Cookie: cookiePair(jarA) },
  body: JSON.stringify({ userId: userIdToRevoke }),
});
const revokeBody = await revoke.json().catch(() => ({}));
expect("administrator revocation accepted", revoke.status === 200, { status: revoke.status, body: revokeBody });

expect("session A no longer authorizes", (await authorizedSessionCheck(jarA)) === false);
expect("session B no longer authorizes", (await authorizedSessionCheck(jarB)) === false);

const fresh = await fetch(`${base}/api/auth/sign-in/username`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Origin": base },
  body: JSON.stringify({ username: options.username, password: options.password }),
});
expect("fresh sign-in still works after revocation", fresh.status === 200, fresh.status);

console.log(`session revocation smoke OK on ${base}: revoking the user's sessions invalidated every concurrent cookie immediately.`);
