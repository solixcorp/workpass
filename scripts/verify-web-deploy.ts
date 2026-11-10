/**
 * Operator tooling: check a deployed origin right after the first deploy.
 * Needs no credentials and changes nothing. It covers what can be verified
 * without signing in: SPA routes, the headers from web/public/_headers,
 * asset caching, that backend paths still reach the Worker, and that the
 * doors meant to be closed are closed.
 *
 *   bun run verify:web --base https://auth.example.com
 *   bun run verify:web --base http://localhost:8799 --window-open
 *
 * --window-open skips the "bootstrap and migrate return 404" checks, for use
 * inside the one-time deployment window. Exits non-zero if any check fails.
 */

const args = Bun.argv.slice(2);
const flag = (name: string) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};
const base = flag("base")?.replace(/\/+$/, "");
const windowOpen = args.includes("--window-open");
if (!base || !/^https?:\/\//.test(base)) {
  console.error("usage: bun run verify:web --base <origin> [--window-open] [--fingerprint-host <host>]");
  process.exit(2);
}

async function configuredFingerprintHost(): Promise<string | null> {
  const explicit = flag("fingerprint-host");
  if (explicit) return explicit;
  try {
    const text = await Bun.file("wrangler.jsonc").text();
    const match = text.match(/"FINGERPRINT_ENDPOINT"\s*:\s*"https?:\/\/([^"/]+)/);
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

type Result = { name: string; ok: boolean; detail: string };
const results: Result[] = [];
const check = (name: string, ok: boolean, detail = "") => results.push({ name, ok, detail });

const get = (path: string, init?: RequestInit) => fetch(base + path, { redirect: "manual", ...init });
const post = (path: string, body = "{}") =>
  fetch(base + path, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", origin: new URL(base!).origin },
    body,
  });

// 1. Every SPA route returns the app shell, including a path that does not exist.
let indexHtml = "";
for (const path of ["/", "/login", "/security", "/admin/users", "/activate", "/no/such/page"]) {
  const response = await get(path);
  const body = await response.text();
  if (path === "/") indexHtml = body;
  const type = response.headers.get("content-type") ?? "";
  check(
    `SPA route ${path} returns the app shell`,
    response.status === 200 && type.includes("text/html") && body.includes('id="root"'),
    `${response.status} ${type}`,
  );
}

// 2. Response headers from web/public/_headers.
const shell = await get("/");
const header = (name: string) => shell.headers.get(name) ?? "";
const csp = header("content-security-policy");
check("CSP is set", csp.includes("default-src 'self'"), csp ? "" : "missing: _headers was not applied");
check("CSP blocks inline and remote scripts", /script-src 'self'/.test(csp) && !/script-src[^;]*'unsafe-(inline|eval)'/.test(csp), csp.match(/script-src[^;]*/)?.[0] ?? "");
check("X-Frame-Options is DENY", header("x-frame-options").toUpperCase() === "DENY", header("x-frame-options"));
check("X-Content-Type-Options is nosniff", header("x-content-type-options").toLowerCase() === "nosniff", header("x-content-type-options"));
check("Referrer-Policy is no-referrer", header("referrer-policy").toLowerCase() === "no-referrer", header("referrer-policy"));
check("HSTS is set", /max-age=\d{7,}/.test(header("strict-transport-security")), header("strict-transport-security"));
check("Permissions-Policy is set", header("permissions-policy").includes("camera=()"), header("permissions-policy"));
check("index.html is revalidated, not immutable", !header("cache-control").includes("immutable"), header("cache-control"));

const fingerprintHost = await configuredFingerprintHost();
if (fingerprintHost) {
  const wildcard = fingerprintHost.replace(/^[^.]+\./, "*.");
  const allowed = csp.includes(fingerprintHost) || csp.includes(wildcard);
  check(
    `CSP allows the Fingerprint host ${fingerprintHost}`,
    allowed,
    allowed ? "" : "update script-src and connect-src in web/public/_headers",
  );
}

// 3. Hashed assets and fonts are cached for a year.
const asset = indexHtml.match(/\/assets\/[^"']+\.js/)?.[0];
if (asset) {
  const response = await get(asset);
  check(`hashed asset ${asset} is immutable`, response.status === 200 && response.headers.get("cache-control")?.includes("immutable") === true, response.headers.get("cache-control") ?? "");
  check("hashed asset is served as JavaScript", (response.headers.get("content-type") ?? "").includes("javascript"), response.headers.get("content-type") ?? "");
} else {
  check("index.html references a hashed asset", false, "no /assets/*.js found");
}
const font = await get("/fonts/SUIT-Variable.woff2");
check("font is immutable", font.status === 200 && font.headers.get("cache-control")?.includes("immutable") === true, `${font.status} ${font.headers.get("cache-control") ?? ""}`);

// 4. Backend paths reach the Worker instead of the SPA fallback.
const health = await get("/health");
check("/health is served by the Worker", health.status === 200 && (health.headers.get("content-type") ?? "").includes("json"), `${health.status} ${health.headers.get("content-type") ?? ""}`);
const login = await get("/auth/login");
const location = login.headers.get("location") ?? "";
check("/auth/login redirects to the authorize endpoint", login.status === 302 && location.includes("/oauth2/v1/authorize"), `${login.status} ${location.slice(0, 60)}`);
const discovery = await get("/.well-known/openid-configuration");
check("OIDC discovery is served", discovery.status === 200 && (discovery.headers.get("content-type") ?? "").includes("json"), `${discovery.status}${discovery.status >= 500 ? ", the D1 schema is probably missing: run /_internal/migrate in the deployment window" : ""}`);
const loginConfig = await get("/api/config/login");
check("/api responses carry the Worker's own security headers", loginConfig.status === 200 && loginConfig.headers.get("cache-control") === "no-store", `${loginConfig.status} ${loginConfig.headers.get("cache-control") ?? ""}`);
const callback = await get("/enduser/callback");
check("/enduser/callback is handled by the Worker, not the SPA fallback", callback.status === 302, String(callback.status));

// 5. Doors that must be closed in production.
const mocks = await get("/dev/mocks/invitation-email");
check("dev mocks are off", mocks.status === 404, String(mocks.status));
const plaintext = await post("/api/auth/sign-in/username", JSON.stringify({ username: "x", password: "x" }));
check("plaintext password sign-in is off", plaintext.status === 404, `${plaintext.status}${plaintext.status !== 404 ? ", ALLOW_PLAINTEXT_PASSWORD_LOGIN must not be set in production" : ""}`);
if (windowOpen) {
  console.log("(window open: migrate and bootstrap checks skipped)");
} else {
  const migrate = await post("/_internal/migrate");
  check("/_internal/migrate is closed", migrate.status === 404, `${migrate.status}${migrate.status !== 404 ? ", redeploy with ENABLE_MIGRATIONS=false" : ""}`);
  const bootstrap = await post("/api/admin/bootstrap");
  check("/api/admin/bootstrap is closed", bootstrap.status === 404, `${bootstrap.status}${bootstrap.status !== 404 ? ", redeploy with ENABLE_ADMIN_BOOTSTRAP=false" : ""}`);
}

let failed = 0;
for (const result of results) {
  if (!result.ok) failed += 1;
  console.log(`${result.ok ? "ok  " : "FAIL"} ${result.name}${result.detail && !result.ok ? `  (${result.detail})` : ""}`);
}
console.log(failed === 0 ? `\nall ${results.length} checks passed` : `\n${failed} of ${results.length} checks failed`);
process.exit(failed === 0 ? 0 : 1);
