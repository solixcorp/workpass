import { beforeAll, describe, expect, test } from "bun:test";
import mod from "../../src/index";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { entitlementClaimForSubject, samlAttributeRelease } from "../../src/claims/protocol-claims";
import { claimReleaseExtension } from "../../src/claims/extension";
import { upsertClaimReleasePolicy } from "../../src/claims/release-policy";

const origin = "http://127.0.0.1:8787";
describe("application entitlements", () => {
  const { db } = createTestD1();
  const env = { DB: db, AUTH_SECRET: "entitlements-secret-0123456789abcdef-012345", AUTH_BASE_URL: origin,
    ENABLE_MIGRATIONS: "true", MIGRATION_TOKEN: "migration-token-0123456789abcdef-0123456789",
    ENABLE_ADMIN_BOOTSTRAP: "true", ADMIN_BOOTSTRAP_TOKEN: "bootstrap-token-0123456789abcdef-0123456789",
    ALLOW_PLAINTEXT_PASSWORD_LOGIN: "true", ENABLE_ATTRIBUTE_CLAIMS: "true",
    AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(5))) } as unknown as Env;
  const jar = new Map<string, string>();
  let user = ""; let group = ""; let otherGroup = ""; let entitlement = "";
  async function call(path: string, method = "GET", body?: unknown, extra: Record<string, string> = {}) {
    const headers: Record<string, string> = { ...extra };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (method !== "GET") headers.Origin = origin;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await mod.fetch(new Request(`${origin}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env,
      { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0]!; const i = pair.indexOf("=");
      if (i > 0) { if (pair.slice(i + 1)) jar.set(pair.slice(0, i), pair.slice(i + 1)); else jar.delete(pair.slice(0, i)); }
    }
    return response;
  }
  const json = async (r: Response): Promise<any> => r.json();
  const url = "/api/admin/applications/test/entitlements";
  beforeAll(async () => {
    expect((await call("/_internal/migrate", "POST", undefined, { Authorization: `Bearer ${env.MIGRATION_TOKEN}` })).status).toBe(200);
    user = (await json(await call("/api/admin/bootstrap", "POST", { email: "admin@ent.test", name: "Admin", username: "entadmin", password: "Detail-7d9Kpw9zL2xQ" }, { Authorization: `Bearer ${env.ADMIN_BOOTSTRAP_TOKEN}` }))).user.id;
    expect((await call("/api/auth/sign-in/username", "POST", { username: "entadmin", password: "Detail-7d9Kpw9zL2xQ" })).status).toBe(200);
    group = (await json(await call("/api/admin/directory-groups", "POST", { name: "ent-members" }))).group.id;
    otherGroup = (await json(await call("/api/admin/directory-groups", "POST", { name: "ent-access" }))).group.id;
    await call(`/api/admin/directory-groups/${group}/members`, "POST", { userId: user });
    await call("/api/admin/applications", "POST", { slug: "test", name: "Test", protocol: "bookmark", launchUrl: "https://example.com" });
    await call("/api/admin/applications/test/enable", "POST");
  });
  test("validates, creates and assigns", async () => {
    expect((await call(url, "POST", { key: "Admin", name: "Admin" })).status).toBe(400);
    const created = await call(url, "POST", { key: "admin", name: "Admin" });
    expect(created.status).toBe(201); entitlement = (await json(created)).entitlement.id;
    expect((await call(url, "POST", { key: "admin", name: "Duplicate" })).status).toBe(409);
    expect((await call(`${url}/${entitlement}`, "PUT", { key: "other", name: "Admin" })).status).toBe(400);
    expect((await call(`${url}/${entitlement}/groups`, "PUT", { groupIds: ["missing"] })).status).toBe(400);
    expect((await call(`${url}/${entitlement}/groups`, "PUT", { groupIds: [group, group] })).status).toBe(200);
    const list = await json(await call(url));
    expect(list.entitlements[0]).toMatchObject({ key: "admin", memberCount: 1, groups: [{ id: group }] });
    expect((await json(await call(`/api/admin/users/${user}/applications`))).applications.find((a: any) => a.slug === "test").entitlements).toEqual(["admin"]);
  });
  test("requires app access and counts distinct holders", async () => {
    await call("/api/admin/applications/test/assignment", "PUT", { mode: "groups", groups: [otherGroup] });
    expect((await json(await call(url))).entitlements[0].memberCount).toBe(0);
    expect((await json(await call(`/api/admin/users/${user}/applications`))).applications.find((a: any) => a.slug === "test").entitlements).toEqual([]);
    await call(`/api/admin/directory-groups/${otherGroup}/members`, "POST", { userId: user });
    expect((await json(await call(url))).entitlements[0].memberCount).toBe(1);
  });
  test("claims are app-specific and follow release gates", async () => {
    await db.prepare("UPDATE applications SET protocol = 'oidc', binding = 'client-a' WHERE slug = 'test'").run();
    expect(await entitlementClaimForSubject(env, user, "oidc:client-a")).toEqual({ entitlements: ["admin"] });
    expect(await entitlementClaimForSubject(env, user, "oidc:client-b")).toEqual({});
    const ext = claimReleaseExtension(env).claims!;
    const args = { user: { id: user }, client: { clientId: "client-a" }, scopes: ["openid"] } as any;
    expect(await (ext.idToken as any)(args)).toMatchObject({ entitlements: ["admin"] });
    expect(await (ext.userInfo as any)(args)).toMatchObject({ entitlements: ["admin"] });
    await db.prepare("UPDATE applications SET protocol = 'saml', binding = 'sp' WHERE slug = 'test'").run();
    expect(await samlAttributeRelease(env, null, null, user, "saml:sp")).toContainEqual({ name: "entitlements", value: "admin" });
    await db.prepare("UPDATE applications SET protocol = 'wsfed', binding = 'realm' WHERE slug = 'test'").run();
    expect(await samlAttributeRelease(env, null, null, user, "wsfed:realm")).toContainEqual({ name: "entitlements", value: "admin" });
    await upsertClaimReleasePolicy(env, { subject: "wsfed:realm", allowAccountClaims: true, allowUserAttributes: false }, user);
    expect(await entitlementClaimForSubject(env, user, "wsfed:realm")).toEqual({});
    await upsertClaimReleasePolicy(env, { subject: "wsfed:realm", allowAccountClaims: true, allowUserAttributes: true, attributeAllowlist: ["other"] }, user);
    expect(await entitlementClaimForSubject(env, user, "wsfed:realm")).toEqual({});
  });
  test("deleting groups and apps cascades assignments", async () => {
    await call(`/api/admin/directory-groups/${group}`, "DELETE");
    expect((await json(await call(url))).entitlements[0].groups).toEqual([]);
    expect((await call("/api/admin/applications/test", "DELETE")).status).toBe(200);
    expect(await db.prepare("SELECT id FROM app_entitlements WHERE id = ?").bind(entitlement).first()).toBeNull();
    jar.clear();
    expect((await call(url)).status).toBe(401);
    expect((await call(url, "POST", { key: "x", name: "X" })).status).toBe(401);
  });
});
