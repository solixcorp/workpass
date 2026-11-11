import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

/** The app integrations an administrator creates: OIDC clients, SAML/WS-Fed/SWA providers, assignment. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Integrations-7d9Kpw9zL2";
// A throwaway self-signed RSA certificate (CN=test-sp.example.com).
const CERT = `-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIUUNerH+5KgQi2hjKSE7dZRFy6gJIwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTdGVzdC1zcC5leGFtcGxlLmNvbTAeFw0yNjExMTEwMjU1
MTZaFw0zNjExMDgwMjU1MTZaMB4xHDAaBgNVBAMME3Rlc3Qtc3AuZXhhbXBsZS5j
b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfzIlOhpzNbLthfsSO
5tBJBPBOvvqRcu0WMbUDtcN9HamLhq3WJp/XGZWFnmbrb45cRbhHfXHweFlTYjGC
2bRnxEMx4YL10dbGXuaIEjzYOngh6f80awqc4yavLQTOLPiaxbw0GfKyrpwxyUhL
8RlQAOc3eawzU+xEaueUoit+NXHfBEnuryUBI0QKLpc1WmbNPa5BCD2rkmh42snX
15vsFooB9UIQgjqR8Oq8JaWYfqGyyNjIISpUdZi8iV7pJm02mDZLUdzZMLz6SGfP
v/XnkcRKFfTxtaDl2Nxe7PJ3L/A1yXrP2Th+TESI/0S2LAuA35spOjVcCEqr5+LU
UFB5AgMBAAGjMjAwMB0GA1UdDgQWBBSv7SdKCnxlYEpCSME81ea7cYK7pzAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBOJQMTMkUwl1rngKFYcifP
B1a1slIhPRBG3n0FyI/b+Myo6pwsjR7W5FGHNenNzMlN7y9nZvKMN1ItYYz5ELpw
eLSeyowErUqacNe+mwFgCIXZeY5p19Snp372fGE5eDiQEU2YzyFKbTMGNb07iY/V
obFuWfuQ1RW1R3y/H4SRHfFe3gfd8jWOt71vCSRoORTgAP+W3szLEtLTB50TP/zD
ozDZIFQgooMSU7OcyWe2i8QoVlzQ1MxK4e6IcikQvyyTmLX8yMBVU6EO+zedKnad
3hqSRHnnWdpbVStAoZOHr4Xd8n9sRoY4sU7Iyj+VGBHh3XCsF0YBByEuMST7PQdx
-----END CERTIFICATE-----`;

describe("app integrations", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "integration-secret-0123456789abcdef-0123456", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string>; form?: string }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    if (init?.form !== undefined) headers["Content-Type"] = "application/x-www-form-urlencoded";
    const response = await mod.fetch(new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers, redirect: "manual",
      body: init?.form ?? (init?.body === undefined ? undefined : JSON.stringify(init.body)),
    }), env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i <= 0) continue;
      const value = pair.slice(i + 1);
      if (value === "") jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), value);
    }
    return response;
  }
  const json = async (response: Response) => (await response.json()) as any;

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    expect((await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@integrations.test", name: "Admin", username: "intadmin", password: PASSWORD },
    })).status).toBe(201);
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "intadmin", password: PASSWORD } })).status).toBe(200);
  });

  test("a web client gets a random id and a secret shown once; the secret is stored hashed", async () => {
    const created = await call("/api/admin/oidc-clients", { method: "POST", body: {
      name: "Wiki", applicationType: "web", grants: ["authorization_code", "refresh_token"],
      redirectUris: ["https://wiki.example.com/callback"], postLogoutRedirectUris: ["https://wiki.example.com"],
    } });
    expect(created.status).toBe(201);
    const { client, clientSecret } = await json(created);
    expect(client.clientId).toMatch(/^[A-Za-z0-9]{24}$/);
    expect(client.confidential).toBe(true);
    expect(client.scopes).toContain("offline_access");
    expect(client.requirePkce).toBe(true);
    expect(clientSecret.length).toBeGreaterThan(30);
    const row = await db.prepare('SELECT clientSecret, disabled FROM "oauthClient" WHERE clientId = ?').bind(client.clientId).first<any>();
    expect(row.clientSecret).not.toBe(clientSecret);
    expect(row.disabled).toBe(1);
    // The read API never returns the secret.
    expect(JSON.stringify(await json(await call(`/api/admin/oidc-clients/${client.clientId}`)))).not.toContain(clientSecret);
  });

  test("redirect addresses and grants are validated", async () => {
    const make = (body: Record<string, unknown>) => call("/api/admin/oidc-clients", { method: "POST", body: { name: "X", applicationType: "web", ...body } });
    expect((await make({ redirectUris: [] })).status).toBe(400);
    expect((await make({ redirectUris: ["http://evil.example.com/cb"] })).status).toBe(400);
    expect((await make({ redirectUris: ["https://a.example.com/*"] })).status).toBe(400);
    expect((await make({ redirectUris: ["https://a.example.com/cb#frag"] })).status).toBe(400);
    expect((await make({ redirectUris: ["myapp://callback"] })).status).toBe(400);
    expect((await make({ redirectUris: ["http://localhost:3000/cb"] })).status).toBe(201);
    expect((await make({ redirectUris: ["https://a.example.com/cb"], grants: ["client_credentials"] })).status).toBe(400);
    // A native app may use its own scheme.
    expect((await call("/api/admin/oidc-clients", { method: "POST", body: { name: "Phone", applicationType: "native", redirectUris: ["myapp://callback"] } })).status).toBe(201);
  });

  test("a SPA is a public client with PKCE and no secret", async () => {
    const { client, clientSecret } = await json(await call("/api/admin/oidc-clients", { method: "POST", body: {
      name: "Spa", applicationType: "spa", redirectUris: ["https://spa.example.com/cb"], requirePkce: false,
    } }));
    expect(clientSecret).toBeNull();
    expect(client.confidential).toBe(false);
    expect(client.requirePkce).toBe(true);
    expect(client.applicationType).toBe("spa");
  });

  test("an API service client can obtain a token with its secret and not with a wrong one", async () => {
    const { client, clientSecret } = await json(await call("/api/admin/oidc-clients", { method: "POST", body: {
      name: "Batch", applicationType: "service", scopes: ["reports.read"],
    } }));
    expect(client.grants).toEqual(["client_credentials"]);
    await db.prepare('UPDATE "oauthClient" SET disabled = 0 WHERE clientId = ?').bind(client.clientId).run();
    const token = (secret: string) => call("/api/auth/oauth2/token", {
      method: "POST", headers: { Authorization: `Basic ${btoa(`${client.clientId}:${secret}`)}` },
      form: new URLSearchParams({ grant_type: "client_credentials", scope: "reports.read" }).toString(),
    });
    const ok = await token(clientSecret);
    expect(ok.status).toBe(200);
    expect((await json(ok)).access_token).toBeTruthy();
    expect((await token("wrong-secret")).status).toBe(401);

    // Rotating replaces the secret: the old one stops working.
    const rotated = await json(await call(`/api/admin/oidc-clients/${client.clientId}/rotate-secret`, { method: "POST" }));
    expect((await token(clientSecret)).status).toBe(401);
    expect((await token(rotated.clientSecret)).status).toBe(200);
  });

  test("an app built on a provider turns the provider on and off, and deleting it removes the provider", async () => {
    const { client } = await json(await call("/api/admin/oidc-clients", { method: "POST", body: {
      name: "Docs", applicationType: "spa", redirectUris: ["https://docs.example.com/cb"],
    } }));
    expect((await call("/api/admin/applications", { method: "POST", body: { slug: "docs", name: "Docs", protocol: "oidc", binding: client.clientId } })).status).toBe(201);
    const disabled = () => db.prepare('SELECT disabled FROM "oauthClient" WHERE clientId = ?').bind(client.clientId).first<any>();
    expect((await disabled()).disabled).toBe(1);
    expect((await call("/api/admin/applications/docs/enable", { method: "POST" })).status).toBe(200);
    expect((await disabled()).disabled).toBe(0);
    expect((await call("/api/admin/applications/docs/disable", { method: "POST" })).status).toBe(200);
    expect((await disabled()).disabled).toBe(1);
    expect((await call("/api/admin/oidc-clients/" + client.clientId, { method: "DELETE" })).status).toBe(409);
    expect((await call("/api/admin/applications/docs", { method: "DELETE" })).status).toBe(200);
    expect(await db.prepare('SELECT 1 AS n FROM "oauthClient" WHERE clientId = ?').bind(client.clientId).first()).toBeNull();
  });

  test("the dashboard client cannot be edited or deleted through the client API", async () => {
    const id = (await db.prepare("SELECT value FROM app_settings WHERE key = 'workpass.client_id'").first<any>()).value;
    expect((await call(`/api/admin/oidc-clients/${id}`, { method: "PATCH", body: { name: "x" } })).status).toBe(409);
    expect((await call(`/api/admin/oidc-clients/${id}`, { method: "DELETE" })).status).toBe(409);
  });

  test("WS-Fed and SWA apps show their provider; a SAML app needs a usable certificate to turn on", async () => {
    expect((await call("/api/admin/wsfed-relying-parties", { method: "POST", body: { realm: "urn:corp:erp", replyUrl: "https://erp.example.com/wsfed" } })).status).toBe(201);
    expect((await call("/api/admin/applications", { method: "POST", body: { slug: "erp", name: "ERP", protocol: "wsfed", binding: "urn:corp:erp" } })).status).toBe(201);
    const view = await json(await call("/api/admin/applications/erp/integration"));
    expect(view.wsfed.replyUrl).toBe("https://erp.example.com/wsfed");
    expect(view.endpoints.signin).toBe(`${ORIGIN}/wsfed/signin`);
    expect((await call("/api/admin/applications/erp/enable", { method: "POST" })).status).toBe(200);
    expect((await db.prepare("SELECT enabled FROM wsfed_relying_parties WHERE realm = 'urn:corp:erp'").first<any>()).enabled).toBe(1);
    expect((await call("/api/admin/applications/erp/integration", { method: "PUT", body: { replyUrl: "http://insecure.example.com" } })).status).toBe(400);
    expect((await call("/api/admin/applications/erp/integration", { method: "PUT", body: { replyUrl: "https://erp2.example.com/wsfed" } })).status).toBe(200);

    expect((await call("/api/admin/swa-applications", { method: "POST", body: { name: "Legacy", origin: "https://legacy.example.com" } })).status).toBe(201);
    expect((await call("/api/admin/applications", { method: "POST", body: { slug: "legacy", name: "Legacy", protocol: "swa", binding: "https://legacy.example.com" } })).status).toBe(201);
    expect((await call("/api/admin/applications/legacy/enable", { method: "POST" })).status).toBe(200);
    expect((await db.prepare("SELECT enabled FROM swa_applications").first<any>()).enabled).toBe(1);

    const bad = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    expect((await call("/api/admin/saml-service-providers", { method: "POST", body: { entityId: "urn:corp:crm", acsUrl: "https://crm.example.com/acs", signingCertificate: bad } })).status).toBe(201);
    expect((await call("/api/admin/applications", { method: "POST", body: { slug: "crm", name: "CRM", protocol: "saml", binding: "urn:corp:crm" } })).status).toBe(201);
    const enable = await call("/api/admin/applications/crm/enable", { method: "POST" });
    expect(enable.status).toBe(409);
    expect((await db.prepare("SELECT enabled FROM applications WHERE slug = 'crm'").first<any>()).enabled).toBe(0);
  });

  test("a SAML app is checked for a usable certificate when it is created, and turns on with a real one", async () => {
    const bad = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    const make = (entityId: string, cert: string) => call("/api/admin/saml-service-providers", { method: "POST", body: {
      entityId, acsUrl: "https://hr.example.com/acs", signingCertificate: cert, verifyCertificate: true,
    } });
    const refused = await make("urn:corp:hr", bad);
    expect(refused.status).toBe(400);
    expect(((await json(refused)).error as string)).toContain("인증서");
    expect(await db.prepare("SELECT 1 AS n FROM saml_service_providers WHERE entity_id = 'urn:corp:hr'").first()).toBeNull();

    expect((await make("urn:corp:hr", CERT)).status).toBe(201);
    expect((await call("/api/admin/applications", { method: "POST", body: { slug: "hr", name: "HR", protocol: "saml", binding: "urn:corp:hr" } })).status).toBe(201);
    expect((await call("/api/admin/applications/hr/enable", { method: "POST" })).status).toBe(200);
    expect((await db.prepare("SELECT enabled FROM saml_service_providers WHERE entity_id = 'urn:corp:hr'").first<any>()).enabled).toBe(1);
    const view = await json(await call("/api/admin/applications/hr/integration"));
    expect(view.saml.acsUrl).toBe("https://hr.example.com/acs");
    expect(view.endpoints.metadata).toBe(`${ORIGIN}/saml/metadata`);
    expect((await call("/api/admin/applications/hr/integration", { method: "PUT", body: { acsUrl: "http://insecure.example.com/acs" } })).status).toBe(400);
    expect((await call("/api/admin/applications/hr/integration", { method: "PUT", body: { acsUrl: "https://hr.example.com/acs2" } })).status).toBe(200);
    expect((await call("/api/admin/applications/hr/disable", { method: "POST" })).status).toBe(200);
    expect((await call("/api/admin/applications/hr", { method: "DELETE" })).status).toBe(200);
    expect(await db.prepare("SELECT 1 AS n FROM saml_service_providers WHERE entity_id = 'urn:corp:hr'").first()).toBeNull();
  });

  test("assigning groups gates the dashboard card and the protocol's own gate together", async () => {
    const group = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "sales", description: "" } }))).group;
    expect((await json(await call("/api/admin/applications/erp/assignment"))).mode).toBe("everyone");
    expect((await call("/api/admin/applications/erp/assignment", { method: "PUT", body: { mode: "groups", groups: [] } })).status).toBe(400);
    expect((await call("/api/admin/applications/erp/assignment", { method: "PUT", body: { mode: "groups", groups: ["nope"] } })).status).toBe(400);
    expect((await call("/api/admin/applications/erp/assignment", { method: "PUT", body: { mode: "groups", groups: [group.id] } })).status).toBe(200);
    const view = await json(await call("/api/admin/applications/erp/assignment"));
    expect(view).toMatchObject({ mode: "groups", groups: [{ id: group.id, name: "sales" }] });
    const gated = await db.prepare("SELECT subject FROM app_policy_groups ORDER BY subject").all<any>();
    expect(gated.results.map((r: any) => r.subject)).toEqual(["app:erp", "wsfed:urn:corp:erp"]);
    expect((await call("/api/admin/applications/erp/assignment", { method: "PUT", body: { mode: "everyone" } })).status).toBe(200);
    expect((await db.prepare("SELECT COUNT(*) AS n FROM app_policy_groups").first<any>()).n).toBe(0);
  });
});
