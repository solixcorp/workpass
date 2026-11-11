import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../src/db/schema";
import {
  createApplication,
  deleteApplication,
  listVisibleApplications,
  setApplicationEnabled,
  updateApplication,
  validateApplicationInput,
} from "../src/applications/store";
import { upsertAppAccessPolicy } from "../src/access/policies";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

async function seededEnv(): Promise<Env & { spEntityId: string; slugs: Record<string, string> }> {
  const testD1 = createTestD1();
  const env = { DB: testD1.db } as unknown as Env & { slugs: Record<string, string> };
  env.slugs = {};
  await ensureApplicationTables(env);
  await env.DB.prepare(
    `INSERT INTO saml_service_providers (id, entity_id, acs_url, signing_certificate, enabled)
     VALUES ('sp-1', 'https://saml-app.example.test', 'https://saml-app.example.test/acs', 'cert', 0)`,
  ).run();
  const accountIdRow = await env.DB.prepare(
    `INSERT INTO accounts (id, name, description, created_by, created_at, updated_at)
     VALUES ('acc-1', 'platform', '', 'u1', '2026-01-01', '2026-01-01')
     RETURNING id`,
  ).first<{ id: string }>();
  await env.DB.prepare(
    `INSERT INTO account_members (account_id, user_id, role, granted_by, granted_at)
     VALUES ('acc-1', 'u1', 'admin', 'u1', '2026-01-01')`,
  ).run();
  void accountIdRow;
  if (!(env as unknown as { slugs: Record<string, string> }).slugs) {
    (env as unknown as { slugs: Record<string, string> }).slugs = {};
  }
  (env as unknown as { accountId?: string }).accountId = "acc-1";
  return env as Env & { slugs: Record<string, string> };
}

const bookmarkInput = {
  slug: "company-wiki",
  name: "Company Wiki",
  description: "Internal handbook",
  protocol: "bookmark" as const,
  binding: null,
  launchUrl: "https://wiki.example.test",
  hideFromDashboard: false,
};

describe("application validation", () => {
  test("slugs, urls and protocols are validated with precise errors", async () => {
    const env = await seededEnv();
    expect((await validateApplicationInput(env, bookmarkInput, "create")).slug).toBe("company-wiki");
    await expect(validateApplicationInput(env, { ...bookmarkInput, slug: "Bad Slug" }, "create")).rejects.toThrow("slug");
    await expect(validateApplicationInput(env, { ...bookmarkInput, name: "" }, "create")).rejects.toThrow("name");
    await expect(validateApplicationInput(env, { ...bookmarkInput, launchUrl: "http://insecure.test" }, "create")).rejects.toThrow("launchUrl");
    await expect(validateApplicationInput(env, { ...bookmarkInput, protocol: "oauth2" }, "create")).rejects.toThrow("protocol");
  });
});

describe("application lifecycle", () => {
  test("creating from the admin form works when optional fields are omitted", async () => {
    const env = await seededEnv();
    // The console sends only slug, name, protocol, launchUrl and categoryGroup.
    const validated = await validateApplicationInput(env, {
      slug: "slack", name: "Slack", protocol: "bookmark", launchUrl: "https://slack.example.test", categoryGroup: null,
    }, "create");
    const created = await createApplication(env, validated as never, "u1");
    expect(created).toMatchObject({ slug: "slack", description: "", binding: null, iconUrl: null, categoryGroup: null, hideFromDashboard: false, enabled: false });
  });

  test("bookmarks require a launch URL, refuse bindings and start disabled", async () => {
    const env = await seededEnv();
    expect((await createApplication(env, bookmarkInput, "u1"))!.enabled).toBe(false);
    await expect(
      createApplication(env, { ...bookmarkInput, slug: "bound-wiki", binding: "https://wiki.example.test" }, "u1"),
    ).rejects.toThrow("must not declare a binding");
    await expect(
      createApplication(env, { ...bookmarkInput, slug: "no-url", launchUrl: null }, "u1"),
    ).rejects.toThrow("requires a launchUrl");
  });

  test("backed protocols validate their binding reference and reject unknown ones", async () => {
    const env = await seededEnv();
    const application = await createApplication(env, {
      slug: "saml-app", name: "SAML App", description: "", protocol: "saml",
      binding: "https://saml-app.example.test", launchUrl: null, hideFromDashboard: false,
    }, "u1");
    expect(application?.protocol).toBe("saml");
    await expect(
      createApplication(env, {
        slug: "orphan", name: "Orphan", description: "", protocol: "saml",
        binding: "https://unknown.example.test", launchUrl: null, hideFromDashboard: false,
      }, "u1"),
    ).rejects.toThrow("not a registered provider");
  });

  test("duplicate slugs resolve to null for the 409 path", async () => {
    const env = await seededEnv();
    await createApplication(env, bookmarkInput, "u1");
    expect(await createApplication(env, { ...bookmarkInput, name: "Duplicate" }, "u1")).toBeNull();
  });

  test("an update saves the group and the external icon URL, and leaves them alone when omitted", async () => {
    const env = await seededEnv();
    await createApplication(env, bookmarkInput, "u1");
    const grouped = await updateApplication(env, "company-wiki", { categoryGroup: "업무 도구", iconUrl: "https://cdn.example.test/wiki.png" });
    expect(grouped).toMatchObject({ categoryGroup: "업무 도구", iconUrl: "https://cdn.example.test/wiki.png" });
    const untouched = await updateApplication(env, "company-wiki", { description: "only this" });
    expect(untouched).toMatchObject({ categoryGroup: "업무 도구", iconUrl: "https://cdn.example.test/wiki.png", description: "only this" });
    const cleared = await updateApplication(env, "company-wiki", { categoryGroup: null, iconUrl: null });
    expect(cleared).toMatchObject({ categoryGroup: null, iconUrl: null });
  });

  test("updates keep the protocol and binding integrity enforced", async () => {
    const env = await seededEnv();
    await createApplication(env, bookmarkInput, "u1");
    const renabled = await updateApplication(env, "company-wiki", { description: "updated", hideFromDashboard: true });
    expect(renabled?.description).toBe("updated");
    expect(renabled?.hideFromDashboard).toBe(true);
    // A patch binding a bookmark is refused by the same finalize rules.
    await expect(
      updateApplication(env, "company-wiki", { binding: "https://saml-app.example.test" }),
    ).rejects.toThrow("must not declare a binding");
    await updateApplication(env, "company-wiki", { binding: null, protocol: "saml" } as never).catch(() => null);
    expect(await deleteApplication(env, "company-wiki")).toBe(true);
    expect(await deleteApplication(env, "company-wiki")).toBe(false);
  });
});

describe("application visibility", () => {
  test("enabled and not-hidden apps pass; the dashboard-hidden ones never show", async () => {
    const env = await seededEnv();
    const visible = await createApplication(env, { ...bookmarkInput, slug: "wiki" }, "u1")!;
    await createApplication(env, { ...bookmarkInput, slug: "hidden", name: "Hidden", hideFromDashboard: true }, "u1");
    await setApplicationEnabled(env, "wiki", true);
    await setApplicationEnabled(env, "hidden", true);
    const listed = await listVisibleApplications(env, "u1");
    expect(listed.map((app) => app.slug)).toEqual(["wiki"]);
    // Enabled lifecycle works both ways: disabled apps disappear from the list.
    await setApplicationEnabled(env, "wiki", false);
    expect(await listVisibleApplications(env, "u1")).toEqual([]);
    void visible;
  });

  test("the app:<slug> policy gates visibility, including the per-account gate", async () => {
    const env = await seededEnv();
    await createApplication(env, { ...bookmarkInput, slug: "member-only" }, "u1");
    await setApplicationEnabled(env, "member-only", true);
    await upsertAppAccessPolicy(env, {
      subject: "app:member-only",
      allowedMethods: "password,passkey",
      sessionTtlSeconds: null,
      bypassWindowSeconds: 0,
      enforcementMode: "enforce",
      requireMfa: false,
      groups: [],
      requiredAccount: "acc-1",
    }, "u1");
    // A member of the required account sees the app; an outsider does not.
    expect((await listVisibleApplications(env, "u1")).map((app) => app.slug)).toEqual(["member-only"]);
    expect(await listVisibleApplications(env, "u2")).toEqual([]);
  });
});
