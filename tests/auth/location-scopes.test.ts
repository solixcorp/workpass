import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { locationGate } from "../../src/security/location-gate";
import { buildCertificateDer, derToPem, fromBase64Url } from "../saml/saml-x509";

/** An administrator reads what a user allowed, when, and the device verdict at that moment. */

const ORIGIN = "http://127.0.0.1:8787";
const PASSWORD = "Activity-7d9Kpw9zL2";
const CALLBACK = "https://wiki.example.com/callback";

describe("scoped sign-in places", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "activity-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", ENABLE_DEVICE_FLOW: "true", ENABLE_CIBA: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  let adminId = "";
  let clientId = "";

  async function call(path: string, init?: { method?: string; body?: unknown; headers?: Record<string, string>; cf?: Record<string, unknown>; cookies?: boolean }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size && init?.cookies !== false) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET" && !headers.Origin) headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const outgoing = new Request(`${ORIGIN}${path}`, {
      method: init?.method ?? "GET", headers, redirect: "manual",
      body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (init?.cf) Object.defineProperty(outgoing, "cf", { value: init.cf });
    const response = await mod.fetch(outgoing, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i <= 0) continue;
      const value = pair.slice(i + 1);
      if (value === "") jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), value);
    }
    return response;
  }
  const json = async (response: Response) => (await response.json()) as any;

  const authorizePath = () => `/api/auth/oauth2/authorize?${new URLSearchParams({
    client_id: clientId, redirect_uri: CALLBACK, response_type: "code", scope: "openid profile email",
    state: "s", code_challenge: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", code_challenge_method: "S256",
  })}`;

  const SEOUL = { latitude: "37.5700", longitude: "126.9800", country: "KR", city: "Seoul" };
  const BUSAN = { latitude: "35.1796", longitude: "129.0756", country: "KR", city: "Busan" };
  const policy = (over: Record<string, unknown>) => ({ mode: "enforce", signal: "network_or_browser", networkMarginKm: 30, maxAccuracyM: 1000, exemptGroups: [], ...over });
  const put = (body: unknown, cf?: Record<string, unknown>) => call("/api/admin/location/policy", { method: "PUT", body, cf });
  const authorize = (cf?: Record<string, unknown>) => call(authorizePath(), { cf });

  beforeAll(async () => {
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", {
      method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` },
      body: { email: "admin@location.test", name: "Admin", username: "locadmin", password: PASSWORD },
    }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "locadmin", password: PASSWORD } })).status).toBe(200);
    clientId = (await json(await call("/api/admin/oidc-clients", { method: "POST", body: { name: "Wiki", applicationType: "web", redirectUris: [CALLBACK] } }))).client.clientId;
  });

  test("group union, exemption, lockout guard and scoped self verdict", async () => {
    const make = async (name: string, latitude: number, longitude: number) => (await json(await call("/api/admin/location/places", { method: "POST", body: { name, latitude, longitude, radiusM: 500 } }))).place;
    const seoul = await make("Seoul", 37.57, 126.98);
    const busan = await make("Busan", 35.1796, 129.0756);
    const group = async (name: string) => (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name, description: "" } }))).group;
    const a = await group("A"); const b = await group("B");
    for (const g of [a, b]) await call(`/api/admin/directory-groups/${g.id}/members`, { method: "POST", body: { userId: adminId } });
    const set = (id: string, placeIds: string[], cf = SEOUL) => call(`/api/admin/location/groups/${id}`, { method: "PUT", body: { placeIds }, cf });
    expect((await set(a.id, [seoul.id])).status).toBe(200);
    expect((await put(policy({ signal: "network", networkMarginKm: 0 }), SEOUL)).status).toBe(200);
    expect((await set(b.id, [busan.id])).status).toBe(200);
    expect((await json(await call("/api/admin/location", { cf: BUSAN }))).self).toMatchObject({ pass: true, placeName: "Busan" });
    expect((await set(a.id, [busan.id])).status).toBe(409);
    expect((await put(policy({ signal: "network", networkMarginKm: 0, exemptGroups: [a.id] }), SEOUL)).status).toBe(200);
    expect((await json(await call("/api/admin/location", { cf: { latitude: "0", longitude: "0" } }))).self.method).toBe("exempt");
    expect((await set(a.id, ["missing"])).status).toBe(400);
    expect((await set("missing", [seoul.id])).status).toBe(404);
    expect((await call(`/api/admin/location/places/${busan.id}`, { method: "DELETE" })).status).toBe(200);
    const view = await json(await call("/api/admin/location"));
    expect(view.groupRules.some((r: any) => r.groupId === b.id)).toBe(false);
  });

  test("app rule is independent of off mode; observe, enforce, proof scope and deletion", async () => {
    await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, created_by, created_at, updated_at) VALUES (?, ?, ?, 'oidc', ?, ?, '2026-01-01', '2026-01-01')").bind("scope-app", "scope-app", "Scope App", clientId, adminId).run();
    const view = await json(await call("/api/admin/location"));
    const place = view.places.find((p: any) => p.name === "Seoul");
    const subject = `oidc:${clientId}`;
    const url = `/api/admin/location/apps/${encodeURIComponent(subject)}`;
    expect(view.applications).toContainEqual({ subject, name: "Scope App", slug: "scope-app" });
    expect((await put(policy({ mode: "off", signal: "network", exemptGroups: [] }), SEOUL)).status).toBe(200);
    expect((await json(await call("/api/admin/location", { cf: BUSAN }))).self.method).toBe("off");
    expect((await call(url, { method: "PUT", body: { placeIds: [], mode: "enforce" } })).status).toBe(400);
    expect((await call(url, { method: "PUT", body: { placeIds: [place.id], mode: "off" } })).status).toBe(400);
    expect((await call("/api/admin/location/apps/oidc%3Amissing", { method: "PUT", body: { placeIds: [place.id], mode: "enforce" } })).status).toBe(404);
    expect((await call(url, { method: "PUT", body: { placeIds: [place.id], mode: "observe" } })).status).toBe(200);
    expect((await authorize(BUSAN)).headers.get("location")).not.toContain("access_denied");
    const observed = await json(await call("/api/admin/audit-events?eventPrefix=authentication.location.observe&limit=1"));
    expect(JSON.parse(observed.events[0].event_context).subject).toBe(subject);
    expect((await call(url, { method: "PUT", body: { placeIds: [place.id], mode: "enforce" } })).status).toBe(200);
    expect((await authorize(BUSAN)).headers.get("location")).toContain("access_denied");
    expect((await authorize(SEOUL)).headers.get("location")).not.toContain("access_denied");
    await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, created_by, created_at, updated_at) VALUES (?, ?, ?, 'saml', ?, ?, '2026-01-01', '2026-01-01')").bind("saml-app", "saml-app", "SAML App", "https://saml.example/id", adminId).run();
    const samlUrl = `/api/admin/location/apps/${encodeURIComponent("saml:https://saml.example/id")}`;
    expect((await call(samlUrl, { method: "PUT", body: { placeIds: [place.id], mode: "enforce" } })).status).toBe(200);
    expect((await call(samlUrl, { method: "DELETE" })).status).toBe(200);
    for (const scopedSubject of ["saml:https://saml.example/id", "wsfed:https://fed.example/realm"]) {
      await db.prepare("INSERT INTO location_app_rules (subject, place_ids, mode) VALUES (?, ?, 'enforce')").bind(scopedSubject, JSON.stringify([place.id])).run();
      const req = new Request(`${ORIGIN}/protocol`);
      Object.defineProperty(req, "cf", { value: BUSAN });
      expect((await locationGate(env, { request: req, userId: adminId, path: "/protocol", subject: scopedSubject })).allowed).toBe(false);
      await db.prepare("DELETE FROM location_app_rules WHERE subject = ?").bind(scopedSubject).run();
    }
    expect((await call(`/api/admin/location/places/${place.id}`, { method: "DELETE" })).status).toBe(200);
    expect((await json(await call("/api/admin/location"))).appRules).toEqual([]);
    expect((await call(url, { method: "DELETE" })).status).toBe(200);
    jar.clear();
    expect((await call(url, { method: "PUT", body: { placeIds: [place.id], mode: "enforce" } })).status).toBe(401);
    expect((await call("/api/admin/location/groups/x", { method: "DELETE" })).status).toBe(401);
  });
});

describe("location proof scope and protocol handlers", () => {
  const { db } = createTestD1();
  const env = {
    DB: db, AUTH_SECRET: "scope-proof-secret-0123456789abcdef-0123456789", AUTH_BASE_URL: ORIGIN,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))),
  } as unknown as Env;
  const jar = new Map<string, string>();
  const seoul = { name: "Proof A", latitude: 37.57, longitude: 126.98, radiusM: 500 };
  const busan = { name: "Proof B", latitude: 35.1796, longitude: 129.0756, radiusM: 500 };
  let adminId = "";
  let a = "";
  let b = "";
  let signing: CryptoKeyPair;
  let certificate = "";

  async function call(path: string, init?: { method?: string; body?: unknown; cf?: Record<string, unknown>; headers?: Record<string, string> }) {
    const headers: Record<string, string> = { ...(init?.headers ?? {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init?.method && init.method !== "GET") headers.Origin = ORIGIN;
    if (init?.body !== undefined) headers["Content-Type"] = "application/json";
    const request = new Request(`${ORIGIN}${path}`, { method: init?.method ?? "GET", headers, redirect: "manual", body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
    if (init?.cf) Object.defineProperty(request, "cf", { value: init.cf });
    const response = await mod.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(";"); const index = pair!.indexOf("=");
      if (index > 0) { const name = pair!.slice(0, index); const value = pair!.slice(index + 1); if (value) jar.set(name, value); else jar.delete(name); }
    }
    return response;
  }
  const json = async (response: Response) => await response.json() as any;
  const putPolicy = (mode: "off" | "observe" | "enforce", signal = "browser") => call("/api/admin/location/policy", { method: "PUT", body: { mode, signal, networkMarginKm: 0, maxAccuracyM: 1000, exemptGroups: [] } });
  const proof = async (place: typeof seoul) => {
    const response = await call("/api/location/proof", { method: "POST", body: { latitude: place.latitude, longitude: place.longitude, accuracy: 20 } });
    expect(await json(response)).toEqual({ ok: true });
    expect(response.headers.get("set-cookie")).toContain("wp_location=");
    return jar.get("wp_location")!;
  };
  const self = async () => (await json(await call("/api/admin/location"))).self;

  beforeAll(async () => {
    signing = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", signing.publicKey);
    certificate = derToPem(buildCertificateDer(fromBase64Url(jwk.n!), fromBase64Url(jwk.e!)));
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", signing.privateKey));
    const encoded = btoa(String.fromCharCode(...pkcs8));
    Object.assign(env, { SAML_IDP_ENTITY_ID: `${ORIGIN}/saml/metadata`, SAML_IDP_SIGNING_CERTIFICATE: certificate, SAML_IDP_SIGNING_PRIVATE_KEY: `-----BEGIN PRIVATE KEY-----\n${encoded.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n` });
    expect((await call("/_internal/migrate", { method: "POST", headers: { Authorization: `Bearer ${env.MIGRATION_TOKEN}` } })).status).toBe(200);
    adminId = (await json(await call("/api/admin/bootstrap", { method: "POST", headers: { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` }, body: { email: "scope-proof@example.test", name: "Admin", username: "proofadmin", password: PASSWORD } }))).user.id;
    expect((await call("/api/auth/sign-in/username", { method: "POST", body: { username: "proofadmin", password: PASSWORD } })).status).toBe(200);
    a = (await json(await call("/api/admin/location/places", { method: "POST", body: seoul }))).place.id;
    b = (await json(await call("/api/admin/location/places", { method: "POST", body: busan }))).place.id;
  });

  test("browser proof belongs to its place, including after group rule changes", async () => {
    expect((await putPolicy("off")).status).toBe(200);
    const tokenA = await proof(seoul);
    expect((await putPolicy("enforce")).status).toBe(200);
    expect(await self()).toMatchObject({ pass: true, method: "browser", placeName: "Proof A" });
    const group = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "Proof-group", description: "" } }))).group;
    expect((await call(`/api/admin/directory-groups/${group.id}/members`, { method: "POST", body: { userId: adminId } })).status).toBe(201);
    const groupUrl = `/api/admin/location/groups/${group.id}`;
    expect((await call(groupUrl, { method: "PUT", body: { placeIds: [a] } })).status).toBe(200);
    expect(await self()).toMatchObject({ pass: true, method: "browser", placeName: "Proof A" });
    // Add a different group rule after the proof was issued. It cannot turn A's proof into B's.
    expect((await putPolicy("observe")).status).toBe(200);
    const other = (await json(await call("/api/admin/directory-groups", { method: "POST", body: { name: "Other-proof-group", description: "" } }))).group;
    expect((await call(`/api/admin/directory-groups/${other.id}/members`, { method: "POST", body: { userId: adminId } })).status).toBe(201);
    expect((await call(`/api/admin/location/groups/${other.id}`, { method: "PUT", body: { placeIds: [b] } })).status).toBe(200);
    expect((await call(groupUrl, { method: "DELETE" })).status).toBe(200);
    expect(await self()).toMatchObject({ pass: false, method: "none" });
    const tokenB = await proof(busan);
    expect((await putPolicy("enforce")).status).toBe(200);
    jar.set("wp_location", tokenA);
    expect(await self()).toMatchObject({ allowed: false, pass: false, method: "none" });
    jar.set("wp_location", tokenB);
    expect(await self()).toMatchObject({ pass: true, method: "browser", placeName: "Proof B" });
    expect((await putPolicy("off")).status).toBe(200);
    expect((await call(`/api/admin/location/groups/${other.id}`, { method: "DELETE" })).status).toBe(200);
    jar.set("wp_location", tokenA);
  });

  test("app rule accepts only its own place proof, even with global mode off", async () => {
    const clientId = (await json(await call("/api/admin/oidc-clients", { method: "POST", body: { name: "Proof OIDC", applicationType: "web", redirectUris: [CALLBACK] } }))).client.clientId;
    await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, created_by, created_at, updated_at) VALUES (?, ?, ?, 'oidc', ?, ?, '2026-01-01', '2026-01-01')").bind("proof-oidc", "proof-oidc", "Proof OIDC", clientId, adminId).run();
    const url = `/api/admin/location/apps/${encodeURIComponent(`oidc:${clientId}`)}`;
    const authorize = `/api/auth/oauth2/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: CALLBACK, response_type: "code", scope: "openid", state: "s", code_challenge: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", code_challenge_method: "S256" })}`;
    expect((await call(url, { method: "PUT", body: { placeIds: [b], mode: "enforce" } })).status).toBe(200);
    expect(new URL((await call(authorize)).headers.get("location")!, ORIGIN).pathname).toBe("/location");
    expect((await call(url, { method: "PUT", body: { placeIds: [a], mode: "enforce" } })).status).toBe(200);
    const allowed = await call(authorize);
    expect(new URL(allowed.headers.get("location")!, ORIGIN).pathname).not.toBe("/location");
    expect(allowed.headers.get("location")).not.toContain("access_denied");
    expect((await call(url, { method: "DELETE" })).status).toBe(200);
  });

  test("a proof stops counting when its place is disabled or deleted", async () => {
    expect((await putPolicy("enforce")).status).toBe(200);
    expect(await self()).toMatchObject({ pass: true, method: "browser", placeName: "Proof A" });
    expect((await call(`/api/admin/location/places/${a}`, { method: "PUT", body: { ...seoul, enabled: false } })).status).toBe(200);
    expect(await self()).toMatchObject({ allowed: false, pass: false, method: "none" });
    expect((await call(`/api/admin/location/places/${a}`, { method: "PUT", body: { ...seoul, enabled: true } })).status).toBe(200);
    expect(await self()).toMatchObject({ pass: true, method: "browser", placeName: "Proof A" });
    expect((await call(`/api/admin/location/places/${a}`, { method: "DELETE" })).status).toBe(200);
    expect(await self()).toMatchObject({ allowed: false, pass: false, method: "none" });
    expect((await putPolicy("off")).status).toBe(200);
    jar.delete("wp_location");
  });

  test("SAML SSO checks its application location rule before assertion issuance", async () => {
    const entity = "https://proof-sp.example/metadata";
    const acs = "https://proof-sp.example/acs";
    await db.prepare("INSERT INTO saml_service_providers (id, entity_id, acs_url, signing_certificate, enabled) VALUES (?, ?, ?, ?, 1)").bind("proof-sp", entity, acs, certificate).run();
    await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, created_by, created_at, updated_at) VALUES (?, ?, ?, 'saml', ?, ?, '2026-01-01', '2026-01-01')").bind("proof-saml", "proof-saml", "Proof SAML", entity, adminId).run();
    const rule = `/api/admin/location/apps/${encodeURIComponent(`saml:${entity}`)}`;
    expect((await call(rule, { method: "PUT", body: { placeIds: [b], mode: "enforce" } })).status).toBe(200);
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_proof-${crypto.randomUUID()}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${ORIGIN}/saml/sso" AssertionConsumerServiceURL="${acs}"><saml:Issuer>${entity}</saml:Issuer></samlp:AuthnRequest>`;
    const compressed = new Uint8Array(await new Response(new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
    const encoded = encodeURIComponent(btoa(String.fromCharCode(...compressed)));
    const sigAlg = encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    const signed = `SAMLRequest=${encoded}&SigAlg=${sigAlg}`;
    const signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signing.privateKey, new TextEncoder().encode(signed)));
    const path = `/saml/sso?${signed}&Signature=${encodeURIComponent(btoa(String.fromCharCode(...signature)))}`;
    const denied = await call(path);
    expect(denied.status).toBe(302);
    expect(denied.headers.get("location")).toContain("access_denied");
    const events = await json(await call("/api/admin/audit-events?eventPrefix=authentication.location.denied&limit=5"));
    expect(events.events.some((event: any) => JSON.parse(event.event_context).subject === `saml:${entity}`)).toBe(true);
    expect((await call(rule, { method: "DELETE" })).status).toBe(200);
    const allowed = await call(path);
    expect(allowed.status).toBe(200);
    expect(await allowed.text()).toContain('name="SAMLResponse"');
  });

  test("WS-Federation sign-in checks its application location rule before token issuance", async () => {
    const realm = "urn:proof:wsfed";
    await db.prepare("INSERT INTO wsfed_relying_parties (id, realm, reply_url, enabled, created_by, created_at) VALUES (?, ?, ?, 1, ?, ?)").bind("proof-fed", realm, "https://proof-fed.example/reply", adminId, new Date().toISOString()).run();
    await db.prepare("INSERT INTO applications (id, slug, name, protocol, binding, created_by, created_at, updated_at) VALUES (?, ?, ?, 'wsfed', ?, ?, '2026-01-01', '2026-01-01')").bind("proof-wsfed", "proof-wsfed", "Proof WS-Fed", realm, adminId).run();
    const rule = `/api/admin/location/apps/${encodeURIComponent(`wsfed:${realm}`)}`;
    expect((await call(rule, { method: "PUT", body: { placeIds: [b], mode: "enforce" } })).status).toBe(200);
    const path = `/wsfed/signin?${new URLSearchParams({ wa: "wsignin1.0", wtrealm: realm })}`;
    const denied = await call(path);
    expect(denied.status).toBe(302);
    expect(denied.headers.get("location")).toContain("access_denied");
    const events = await json(await call("/api/admin/audit-events?eventPrefix=authentication.location.denied&limit=5"));
    expect(events.events.some((event: any) => JSON.parse(event.event_context).subject === `wsfed:${realm}`)).toBe(true);
    expect((await call(rule, { method: "DELETE" })).status).toBe(200);
    const allowed = await call(path);
    expect(allowed.status).toBe(200);
    expect(await allowed.text()).toContain('name="wresult"');
  });
});
