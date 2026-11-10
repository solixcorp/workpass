import { describe, expect, test } from "bun:test";

import mod from "../../src/index";
import type { Env } from "../../src/env";

/**
 * Regression: the MFA sub-router used to be mounted "/" with /mfa/... paths,
 * leaving every /api/mfa/... endpoint silently unroutable (404) even though
 * all callers, audit records, and documents pointed at /api/mfa/....
 * The router is now mounted under /api; these assertions pin that.
 */

const stubEnv = {
  AUTH_BASE_URL: "http://127.0.0.1:8787",
  DB: {
    prepare() {
      return { bind() { return this; }, async first() { return null; }, async run() { return this; }, async all() { return { results: [] }; } };
    },
    async batch() { return []; },
  },
} as unknown as Env;

async function statusOf(request: Request): Promise<number> {
  const response = await mod.fetch(request, stubEnv, { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext);
  return response.status;
}

describe("MFA endpoints are routed under /api/mfa", () => {
  test("POST /api/mfa/hotp/enroll is not a 404", async () => {
    const status = await statusOf(new Request("http://x/api/mfa/hotp/enroll", {
      method: "POST",
      headers: { Origin: "http://127.0.0.1:8787", "Content-Type": "application/json" },
      body: JSON.stringify({ label: "probe" }),
    }));
    expect(status).not.toBe(404);
  });

  test("GET /api/mfa/second-factor is not a 404", async () => {
    const status = await statusOf(new Request("http://x/api/mfa/second-factor"));
    expect(status).not.toBe(404);
  });

  test("the bare /mfa... paths no longer exist", async () => {
    const status = await statusOf(new Request("http://x/mfa/second-factor"));
    expect(status).toBe(404);
  });
});
