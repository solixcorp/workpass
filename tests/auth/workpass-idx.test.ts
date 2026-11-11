import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/**
 * WorkPass first-party OAuth client + remediation-driven identify, end to end
 * against a real Better Auth instance and the Worker router.
 */

const ORIGIN = "http://127.0.0.1:8787";

function testEnv(db: D1Database): Env {
  return {
    DB: db,
    AUTH_SECRET: "workpass-test-secret-0123456789abcdef-0123",
    AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true",
    MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true",
    ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    FINGERPRINT_PUBLIC_API_KEY: "public-key-for-tests",
    FINGERPRINT_MODE: "observe",
    FINGERPRINT_REGION: "eu",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
  } as unknown as Env;
}

async function run(request: Request, env: Env): Promise<Response> {
  return mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
}

describe("WorkPass client and IDX identify", () => {
  const { db } = createTestD1();
  const env = testEnv(db);
  const jar = new Map<string, string>();

  async function call(
    path: string,
    init?: { method?: "GET" | "POST" | "DELETE" | "PATCH"; body?: unknown; origin?: boolean; headers?: Record<string, string>; cookies?: boolean },
  ): Promise<Response> {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (init?.cookies !== false && jar.size) {
      headers.Cookie = Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
    }
    if (init?.origin) headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await run(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET",
      headers,
      redirect: "manual",
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    }), env);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!;
      const separator = pair.indexOf("=");
      if (separator <= 0) continue;
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      if (value === "") jar.delete(name);
      else jar.set(name, value);
    }
    return response;
  }

  beforeAll(async () => {
    const migrate = await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    expect(migrate.status).toBe(200);
    const bootstrap = await call("/api/admin/bootstrap", {
      method: "POST", origin: true,
      headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@workpass.test", name: "WorkPass Admin", username: "wpadmin", password: "WorkPassOnly-7d9Kpw9zL2" },
    });
    expect(bootstrap.status).toBe(201);
  });

  async function storedClientId(): Promise<string> {
    const row = await db.prepare("SELECT value FROM app_settings WHERE key = 'workpass.client_id'").first<{ value: string }>();
    return row!.value;
  }

  test("migration creates one random client id, stored in the database", async () => {
    const id = await storedClientId();
    expect(id).toMatch(/^[A-Za-z0-9]{24}$/);
    expect(id).not.toBe("workpass");
    // Running the migration again keeps the same value.
    await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    expect(await storedClientId()).toBe(id);
    const app = await db.prepare("SELECT binding FROM applications WHERE slug = 'workpass-dashboard'").first<{ binding: string }>();
    expect(app?.binding).toBe(id);
    const config = await (await call("/api/config/login", { cookies: false })).json() as { app: { id: string } };
    expect(config.app.id).toBe(id);
  });

  test("an old deployment's fixed id is renamed everywhere, keeping its tokens and policy", async () => {
    const id = await storedClientId();
    // Put the database back into the old shape.
    await db.prepare("DELETE FROM app_settings WHERE key = 'workpass.client_id'").run();
    await db.prepare('UPDATE "oauthClient" SET clientId = ? WHERE clientId = ?').bind("workpass", id).run();
    await db.prepare("UPDATE applications SET binding = 'workpass' WHERE slug = 'workpass-dashboard'").run();
    await db.prepare(
      `INSERT INTO app_access_policies (subject, allowed_methods, bypass_window_seconds, enforcement_mode, require_mfa, updated_by, updated_at)
       VALUES ('oidc:workpass', 'password', 0, 'enforce', 0, 'test', ?)`,
    ).bind(new Date().toISOString()).run();

    await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    const renamed = await storedClientId();
    expect(renamed).toMatch(/^[A-Za-z0-9]{24}$/);
    expect(await db.prepare('SELECT 1 AS n FROM "oauthClient" WHERE clientId = ?').bind("workpass").first()).toBeNull();
    expect(await db.prepare('SELECT 1 AS n FROM "oauthClient" WHERE clientId = ?').bind(renamed).first()).not.toBeNull();
    const policy = await db.prepare("SELECT subject FROM app_access_policies WHERE subject = ?").bind(`oidc:${renamed}`).first();
    expect(policy).not.toBeNull();
    expect(await db.prepare("SELECT 1 AS n FROM app_access_policies WHERE subject = 'oidc:workpass'").first()).toBeNull();
    await db.prepare("DELETE FROM app_access_policies WHERE subject = ?").bind(`oidc:${renamed}`).run();
  });

  test("migration seeds the WorkPass client as a PKCE-only, consent-free public client", async () => {
    const row = await db.prepare(
      'SELECT name, scopes, redirectUris, skipConsent, requirePKCE, tokenEndpointAuthMethod, clientSecret FROM "oauthClient" WHERE clientId = ?',
    ).bind(await storedClientId()).first<Record<string, unknown>>();
    expect(row?.name).toBe("WorkPass Dashboard");
    expect(row?.skipConsent).toBe(1);
    expect(row?.requirePKCE).toBe(1);
    expect(row?.tokenEndpointAuthMethod).toBe("none");
    expect(row?.clientSecret).toBeNull();
    expect(JSON.parse(row?.redirectUris as string)).toEqual([`${ORIGIN}/enduser/callback`]);
    const scopes = JSON.parse(row?.scopes as string) as string[];
    expect(scopes).toContain("workpass.enduser.dashboard.read");
    expect(scopes).toContain("workpass.myAccount.sessions.manage");

    // Re-running the migration keeps exactly one row.
    await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } });
    const count = await db.prepare('SELECT COUNT(*) AS count FROM "oauthClient" WHERE clientId = ?').bind(await storedClientId()).first<{ count: number }>();
    expect(count?.count).toBe(1);
  });

  test("WorkPass scopes stay out of public discovery", async () => {
    const response = await call("/.well-known/openid-configuration", { cookies: false });
    const body = await response.json() as { scopes_supported?: string[] };
    expect(body.scopes_supported).toContain("openid");
    expect(body.scopes_supported?.some((scope) => scope.startsWith("workpass."))).toBeFalse();
  });

  test("login config exposes only the public Fingerprint key", async () => {
    const response = await call("/api/config/login", { cookies: false });
    const body = await response.json() as { app: { name: string }; fingerprint: { publicKey: string; region: string } | null };
    expect(body.app.name).toBe("WorkPass Dashboard");
    expect(body.app.icon).toBe("/workpass.svg");
    expect((body.app as { signInTitle: string }).signInTitle).toBe("WorkPass Dashboard에 로그인");
    expect((body as { organization: { name: string } }).organization.name).toBe("Solixcorp");
    expect(body.fingerprint).toEqual({ publicKey: "public-key-for-tests", region: "eu", endpoint: null });
    expect(body.login).toEqual({ passkey: true });
    expect(JSON.stringify(body)).not.toContain("SERVER");
  });

  test("the dashboard is listed as an app and cannot be deleted, disabled or renamed", async () => {
    await call("/api/auth/sign-in/username", {
      method: "POST", origin: true, body: { username: "wpadmin", password: "WorkPassOnly-7d9Kpw9zL2" },
    });
    const list = await (await call("/api/admin/applications")).json() as { applications: Array<{ slug: string; name: string; enabled: boolean; protected: boolean }> };
    const row = list.applications.find((app) => app.slug === "workpass-dashboard");
    expect(row).toMatchObject({ name: "WorkPass Dashboard", enabled: true, protected: true });

    expect((await call("/api/admin/applications/workpass-dashboard", { method: "DELETE", origin: true })).status).toBe(409);
    expect((await call("/api/admin/applications/workpass-dashboard/disable", { method: "POST", origin: true })).status).toBe(409);
    const rename = await call("/api/admin/applications/workpass-dashboard", { method: "PATCH", origin: true, body: { name: "Other" } });
    expect(rename.status).toBe(409);
    await call("/api/auth/sign-out", { method: "POST", origin: true, body: {} });
  });

  test("device nonce and IDX introspect/identify/challenge return remediation-driven states", async () => {
    const nonce = await (await call("/api/v1/internal/device/nonce", { method: "POST", cookies: false })).json() as { nonce: string; expiresAt: string };
    expect(nonce.nonce.length).toBeGreaterThan(20);
    expect(Date.parse(nonce.expiresAt)).toBeGreaterThan(Date.now());

    const introspect = await (await call("/idp/idx/introspect", { method: "POST", body: {}, cookies: false })).json() as any;
    expect(introspect.intent).toBe("LOGIN");
    expect(introspect.remediation.value[0].name).toBe("identify");
    expect(introspect.app.value.label).toBe("WorkPass Dashboard");
    expect(String(introspect.authentication.value.request.scope)).toContain("workpass.users.read.self");

    const identify = async (identifier: string, stateHandle: string) =>
      await (await call("/idp/idx/identify", { method: "POST", body: { identifier, stateHandle }, cookies: false })).json() as any;

    const known = await identify("admin@workpass.test", introspect.stateHandle);
    const unknown = await identify("nobody@workpass.test", introspect.stateHandle);
    for (const view of [known, unknown]) {
      expect(view.remediation.value[0].name).toMatch(/^(challenge-authenticator|select-authenticator-authenticate)$/);
      expect(view.authenticators.value.some((entry: any) => entry.key === "password")).toBeTrue();
      expect(view.authenticatorEnrollments.value.length).toBe(view.authenticators.value.length);
      expect(view.stateHandle.startsWith("02.id.")).toBeTrue();
    }
    expect(known.user.value.identifier).toBe("admin@workpass.test");
    expect(unknown.user.value.identifier).toBe("nobody@workpass.test");

    // Selecting a method moves to its challenge; an unknown id is refused.
    if (known.remediation.value[0].name === "select-authenticator-authenticate") {
      const passwordId = known.authenticators.value.find((entry: any) => entry.key === "password").id;
      const challenged = await (await call("/idp/idx/challenge", {
        method: "POST", cookies: false,
        body: { authenticator: { id: passwordId }, stateHandle: known.stateHandle },
      })).json() as any;
      expect(challenged.remediation.value[0].name).toBe("challenge-authenticator");
      expect(challenged.currentAuthenticatorEnrollment.value.key).toBe("password");
      expect(challenged.remediation.value[0].protocol).toBe("opaque");
      const refused = await call("/idp/idx/challenge", {
        method: "POST", cookies: false,
        body: { authenticator: { id: "nope" }, stateHandle: known.stateHandle },
      });
      expect(refused.status).toBe(400);

      // "Another way" (no authenticator) returns the choice screen again.
      const again = await (await call("/idp/idx/challenge", {
        method: "POST", cookies: false, body: { stateHandle: challenged.stateHandle },
      })).json() as any;
      expect(again.remediation.value[0].name).toBe("select-authenticator-authenticate");
      expect(challenged.remediation.value[0].ui.action).toBe("opaque-password");
      expect(challenged.remediation.value[0].ui.alternatives.some((entry: any) => entry.action === "switch-method")).toBeTrue();
    }
    expect(JSON.stringify([introspect, known, unknown])).not.toMatch(/okta/i);

    // The screen is defined by the server: every remediation carries its own
    // copy, fields, choices and alternative actions.
    const identifyUi = introspect.remediation.value[0].ui;
    expect(identifyUi.title).toBe("이메일을 입력하세요");
    expect(identifyUi.action).toBe("identify");
    expect(identifyUi.fields[0]).toMatchObject({ name: "identifier", kind: "email" });
    expect(identifyUi.submit.label).toBe("다음");
    expect(identifyUi.alternatives.some((entry: any) => entry.action === "passkey")).toBeTrue();
    for (const view of [known, unknown]) {
      const ui = view.remediation.value[0].ui;
      expect(typeof ui.title).toBe("string");
      expect(ui.alternatives.some((entry: any) => entry.action === "cancel")).toBeTrue();
      if (view.remediation.value[0].name === "select-authenticator-authenticate") {
        expect(ui.options.length).toBe(view.authenticators.value.length);
      }
    }

    // The same unknown identifier always gets the same answer.
    const again = await identify("nobody@workpass.test", introspect.stateHandle);
    expect(again.authenticators.value).toEqual(unknown.authenticators.value);

    // The handle is tamper-evident and bound to nothing the caller can forge.
    const forged = await call("/idp/idx/identify", {
      method: "POST", cookies: false,
      body: { identifier: "admin@workpass.test", stateHandle: `${introspect.stateHandle.slice(0, -4)}AAAA` },
    });
    expect(forged.status).toBe(401);
  });

  test("allowed authenticators follow the WorkPass access policy", async () => {
    await db.prepare(
      `INSERT INTO app_access_policies (subject, allowed_methods, bypass_window_seconds, enforcement_mode, require_mfa, updated_by, updated_at)
       VALUES (?, 'password', 0, 'enforce', 0, 'test', ?)`,
    ).bind(`oidc:${await storedClientId()}`, new Date().toISOString()).run();
    const { stateHandle } = await (await call("/idp/idx/introspect", { method: "POST", body: {}, cookies: false })).json() as { stateHandle: string };
    const view = await (await call("/idp/idx/identify", {
      method: "POST", cookies: false, body: { identifier: "admin@workpass.test", stateHandle },
    })).json() as any;
    expect(view.authenticators.value.map((entry: any) => entry.key)).toEqual(["password"]);
    expect(view.remediation.value[0].name).toBe("challenge-authenticator");
    await db.prepare("DELETE FROM app_access_policies WHERE subject = ?").bind(`oidc:${await storedClientId()}`).run();
  });

  test("an unauthenticated authorize hands off to the SPA with a verified signed query", async () => {
    const login = await call("/auth/login?redirect=%2Fsecurity", { cookies: false });
    expect(login.status).toBe(302);
    const authorizeUrl = new URL(login.headers.get("location")!);
    expect(authorizeUrl.pathname).toBe("/oauth2/v1/authorize");
    // Plain OAuth2 shape: alphabetical params and %20-separated scopes.
    expect(authorizeUrl.search).toContain("&scope=openid%20profile%20email%20workpass.users.read.self");
    expect(authorizeUrl.search).not.toContain("+");
    expect([...authorizeUrl.searchParams.keys()].slice(0, 3)).toEqual(["client_id", "code_challenge", "code_challenge_method"]);
    expect(authorizeUrl.searchParams.get("client_id")).toBe(await storedClientId());
    expect(authorizeUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(login.headers.get("set-cookie")).toContain("wp_oauth=");
    expect(login.headers.get("set-cookie")).toContain("HttpOnly");
    jar.delete("wp_oauth");

    const authorize = await call(`${authorizeUrl.pathname}${authorizeUrl.search}`, { cookies: false });
    expect(authorize.status).toBe(302);
    const signIn = new URL(authorize.headers.get("location")!, ORIGIN);
    expect(signIn.pathname).toBe("/sign-in");

    const handoff = await call(`${signIn.pathname}${signIn.search}`, { cookies: false });
    expect(handoff.status).toBe(302);
    const spa = new URL(handoff.headers.get("location")!, ORIGIN);
    expect(spa.pathname).toBe("/login");
    expect(spa.searchParams.get("oq")).toContain("sig=");

    const tampered = await call(`${signIn.pathname}${signIn.search}&scope=openid+workpass.admin`, { cookies: false });
    expect(tampered.status).toBe(400);
    const bare = await call("/sign-in", { cookies: false });
    expect(bare.status).toBe(400);
  });

  test("signed-in browser completes the code + PKCE round trip server-side", async () => {
    const signIn = await call("/api/auth/sign-in/username", {
      method: "POST", origin: true, body: { username: "wpadmin", password: "WorkPassOnly-7d9Kpw9zL2" },
    });
    expect(signIn.status).toBe(200);

    const login = await call("/auth/login?redirect=%2Fsecurity");
    const authorizeUrl = new URL(login.headers.get("location")!);
    const state = authorizeUrl.searchParams.get("state")!;

    const authorize = await call(`${authorizeUrl.pathname}${authorizeUrl.search}`);
    expect(authorize.status).toBe(302);
    const callbackUrl = new URL(authorize.headers.get("location")!);
    expect(callbackUrl.pathname).toBe("/enduser/callback");
    expect(callbackUrl.searchParams.get("state")).toBe(state);
    expect(callbackUrl.searchParams.get("code")).toBeTruthy();

    // A tampered state is refused and the flow cookie is cleared.
    const savedFlow = jar.get("wp_oauth")!;
    const badState = await call(`/enduser/callback?code=${callbackUrl.searchParams.get("code")}&state=wrong`);
    expect(badState.headers.get("location")).toBe(`${ORIGIN}/login?error=oauth`);
    jar.set("wp_oauth", savedFlow);

    const callback = await call(`${callbackUrl.pathname}${callbackUrl.search}`);
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe(`${ORIGIN}/security`);

    const audited = await db.prepare(
      "SELECT outcome FROM audit_events WHERE event_type = 'authentication.workpass.login' ORDER BY log_pos DESC LIMIT 1",
    ).first<{ outcome: string }>();
    expect(audited?.outcome).toBe("success");
  });

  test("a signed OIDC request resumes through /oauth2/continue after SPA sign-in", async () => {
    const saved = new Map(jar);
    jar.clear();
    const login = await call("/auth/login", { cookies: false });
    const authorizeUrl = new URL(login.headers.get("location")!);
    jar.delete("wp_oauth");
    const authorize = await call(`${authorizeUrl.pathname}${authorizeUrl.search}`, { cookies: false });
    const handoff = await call(new URL(authorize.headers.get("location")!, ORIGIN).pathname + new URL(authorize.headers.get("location")!, ORIGIN).search, { cookies: false });
    const oq = new URL(handoff.headers.get("location")!, ORIGIN).searchParams.get("oq")!;

    const signIn = await call("/api/auth/sign-in/username", {
      method: "POST", origin: true, body: { username: "wpadmin", password: "WorkPassOnly-7d9Kpw9zL2" },
    });
    expect(signIn.status).toBe(200);

    const forged = await call("/api/auth/oauth2/continue", {
      method: "POST", origin: true, body: { postLogin: true, oauth_query: `${oq}&scope=openid` },
    });
    expect(forged.status).toBe(400);

    const resumed = await call("/api/auth/oauth2/continue", {
      method: "POST", origin: true, body: { postLogin: true, oauth_query: oq },
    });
    expect(resumed.status).toBe(200);
    const body = await resumed.json() as { redirect?: boolean; url?: string };
    expect(body.redirect).toBeTrue();
    const target = new URL(body.url!);
    expect(target.origin + target.pathname).toBe(`${ORIGIN}/enduser/callback`);
    expect(target.searchParams.get("code")).toBeTruthy();

    jar.clear();
    for (const [name, value] of saved) jar.set(name, value);
  });

  test("protocol endpoints hand unauthenticated browsers to the WorkPass sign-in, never a page of their own", async () => {
    const wsfed = await call("/wsfed/signin?wa=wsignin1.0&wtrealm=urn:none", { cookies: false });
    // An unregistered realm is refused before any sign-in is offered.
    expect(wsfed.status).not.toBe(200);
    const saml = await call("/saml/sso", { cookies: false });
    expect(saml.headers.get("content-type") ?? "").not.toContain("text/html");
  });

  test("an open-redirect return target collapses to the portal root", async () => {
    const login = await call("/auth/login?redirect=//evil.example/x", { cookies: true });
    const authorizeUrl = new URL(login.headers.get("location")!);
    const authorize = await call(`${authorizeUrl.pathname}${authorizeUrl.search}`);
    const callbackUrl = new URL(authorize.headers.get("location")!);
    const callback = await call(`${callbackUrl.pathname}${callbackUrl.search}`);
    expect(callback.headers.get("location")).toBe(`${ORIGIN}/`);
  });
});
