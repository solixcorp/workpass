import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { ensureApplicationTables } from "../src/db/schema";
import { createApplication } from "../src/applications/store";
import {
  deleteApplicationIcon,
  getApplicationIcon,
  iconDisplayPath,
  iconObjectKey,
  putApplicationIcon,
  sniffImageType,
} from "../src/applications/icons";
import { applicationIconRoutes } from "../src/applications/icon-routes";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

/** A minimal R2 bucket stub over an in-memory map (put/get/delete + httpMetadata). */
class TestR2 {
  objects = new Map<string, { bytes: Uint8Array; contentType?: string }>();
  async put(key: string, value: Uint8Array, options?: { httpMetadata?: { contentType?: string } }) {
    this.objects.set(key, { bytes: new Uint8Array(value), contentType: options?.httpMetadata?.contentType });
    return { key };
  }
  async get(key: string) {
    const object = this.objects.get(key);
    if (!object) return null;
    return {
      body: object.bytes,
      httpMetadata: { contentType: object.contentType },
    };
  }
  async delete(key: string) {
    return this.objects.delete(key);
  }
}

async function seededEnv(bucket: TestR2): Promise<Env & { appSlug: string }> {
  const testD1 = createTestD1();
  const env = {
    DB: testD1.db,
    APPLICATION_ICONS: bucket as unknown as R2Bucket,
  } as unknown as Env & { appSlug: string };
  await ensureApplicationTables(env);
  const application = await createApplication(env, {
    slug: "wiki", name: "Wiki", description: "", protocol: "bookmark",
    binding: null, launchUrl: "https://wiki.example.test", iconUrl: null, categoryGroup: null,
    hideFromDashboard: false,
  }, "u1");
  (env as unknown as { appSlug: string }).appSlug = application!.slug;
  return env;
}

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0]);
const TEXT = new TextEncoder().encode("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>");
const GARBAGE = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]);

describe("icon type sniffing", () => {
  test("magic bytes map to the allowlist", () => {
    expect(sniffImageType(PNG)?.contentType).toBe("image/png");
    expect(sniffImageType(JPEG)?.contentType).toBe("image/jpeg");
    expect(sniffImageType(TEXT)?.contentType).toBe("image/svg+xml");
    expect(sniffImageType(GARBAGE)).toBeNull();
  });
});

describe("icon upload lifecycle", () => {
  test("upload stores the object, records the key and serves the stable path", async () => {
    const bucket = new TestR2();
    const env = await seededEnv(bucket);
    const stored = await putApplicationIcon(env, {
      slug: "wiki", name: "Wiki", description: "", protocol: "bookmark", binding: null,
      launchUrl: null, iconUrl: null, iconKey: null, categoryGroup: null,
      hideFromDashboard: false, enabled: true, createdBy: "u1", createdAt: "",
    }, PNG);
    expect(stored?.contentType).toBe("image/png");
    expect(bucket.objects.has(iconObjectKey("wiki"))).toBe(true);
    expect(iconDisplayPath({ slug: "wiki", iconKey: iconObjectKey("wiki"), iconUrl: "https://elsewhere.test/icon.png" })).toBe("/application/wiki/icon");

    // The public GET serves the bytes with the sniffed content type.
    const hono = new Hono<{ Bindings: Env }>();
    hono.route("/", applicationIconRoutes);
    const response = await hono.request("/application/wiki/icon", {}, env);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("image/png");
  });

  test("svg icons are served under a restrictive CSP", async () => {
    const bucket = new TestR2();
    const env = await seededEnv(bucket);
    await putApplicationIcon(env, {
      slug: "wiki", name: "Wiki", description: "", protocol: "bookmark", binding: null,
      launchUrl: null, iconUrl: null, iconKey: null, categoryGroup: null,
      hideFromDashboard: false, enabled: true, createdBy: "u1", createdAt: "",
    }, TEXT);
    const hono = new Hono<{ Bindings: Env }>();
    hono.route("/", applicationIconRoutes);
    const response = await hono.request("/application/wiki/icon", {}, env);
    expect(response.headers.get("content-type")).toBe("image/svg+xml");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  test("a non-image or oversized upload is rejected, nothing stored", async () => {
    const bucket = new TestR2();
    const env = await seededEnv(bucket);
    const junk = await putApplicationIcon(env, {
      slug: "wiki", name: "Wiki", description: "", protocol: "bookmark", binding: null,
      launchUrl: null, iconUrl: null, iconKey: null, categoryGroup: null,
      hideFromDashboard: false, enabled: true, createdBy: "u1", createdAt: "",
    }, GARBAGE);
    expect(junk).toBeNull();
    expect(bucket.objects.size).toBe(0);
    const oversized = await putApplicationIcon(env, {
      slug: "wiki", name: "Wiki", description: "", protocol: "bookmark", binding: null,
      launchUrl: null, iconUrl: null, iconKey: null, categoryGroup: null,
      hideFromDashboard: false, enabled: true, createdBy: "u1", createdAt: "",
    }, new Uint8Array(1024 * 1024 + 1));
    expect(oversized).toBeNull();
  });

  test("deleting the icon clears the object and the row key", async () => {
    const bucket = new TestR2();
    const env = await seededEnv(bucket);
    const row = {
      slug: "wiki", name: "Wiki", description: "", protocol: "bookmark" as const, binding: null,
      launchUrl: null, iconUrl: null, iconKey: null, categoryGroup: null,
      hideFromDashboard: false, enabled: true, createdBy: "u1", createdAt: "",
    };
    await putApplicationIcon(env, row, PNG);
    const uploaded = { ...row, iconKey: iconObjectKey("wiki") };
    expect(await deleteApplicationIcon(env, "wiki")).toBe(true);
    expect(bucket.objects.size).toBe(0);
    expect(await getApplicationIcon(env, "wiki")).toBeNull();
    // The DB row is authoritative: a cleared key reports nothing to delete.
    expect(await deleteApplicationIcon(env, "wiki")).toBe(false);
  });
});
