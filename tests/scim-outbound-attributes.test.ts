import { describe, expect, test } from "bun:test";
import {
  createScimUser,
  patchScimUser,
  CUSTOM_ATTRIBUTES_URN,
  type ScimTarget,
} from "../src/scim/client";

const TARGET: ScimTarget = {
  baseUrl: "https://scim.example.test/v2",
  bearerToken: "target-token-0123456789abcdef",
};

/** Capture the last outbound request body through a stubbed fetch. */
let lastBody: Record<string, unknown> | null = null;

function stubFetch(status: number, responseBody: unknown): void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    lastBody = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : null;
    return new Response(JSON.stringify(responseBody), { status });
  }) as typeof fetch;
  (globalThis.fetch as { __restore?: () => void }).__restore = () => {
    globalThis.fetch = original;
  };
}

function restoreFetch(): void {
  (globalThis.fetch as { __restore?: () => void }).__restore?.();
}

const REMOTE_USER = { id: "remote-1", externalId: "local-1" };

describe("outbound SCIM attribute release", () => {
  test("create carries the extension only when custom attributes are supplied", async () => {
    stubFetch(201, REMOTE_USER);
    try {
      await createScimUser(TARGET, { externalId: "local-1", userName: "u", displayName: "U", email: "u@example.test", active: true });
      expect(lastBody!.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:User"]);
      expect(lastBody![CUSTOM_ATTRIBUTES_URN]).toBeUndefined();

      await createScimUser(TARGET, {
        externalId: "local-1", userName: "u", displayName: "U", email: "u@example.test", active: true,
        customAttributes: { employeeType: "contractor", badge: 7 },
      });
      expect((lastBody!.schemas as string[]).includes(CUSTOM_ATTRIBUTES_URN)).toBe(true);
      expect(lastBody![CUSTOM_ATTRIBUTES_URN]).toEqual({ employeeType: "contractor", badge: 7 });
      // Core SCIM fields are untouched by the extension.
      expect(lastBody!.userName).toBe("u");
      expect(lastBody!.active).toBe(true);
    } finally {
      restoreFetch();
    }
  });

  test("patch moves core attributes and the extension as separate operations", async () => {
    stubFetch(200, {});
    try {
      await patchScimUser(TARGET, "remote-1", {
        email: "u@example.test",
        customAttributes: { team: "core" },
      });
      const operations = lastBody!.Operations as Array<Record<string, unknown>>;
      expect(operations).toHaveLength(2);
      expect(operations[0]).toEqual({
        op: "replace",
        value: { emails: [{ value: "u@example.test", primary: true }] },
      });
      expect(operations[1]).toEqual({
        op: "replace",
        path: CUSTOM_ATTRIBUTES_URN,
        value: { team: "core" },
      });
    } finally {
      restoreFetch();
    }
  });

  test("a deactivation payload never carries attribute data", async () => {
    stubFetch(200, {});
    try {
      await patchScimUser(TARGET, "remote-1", { active: false });
      const operations = lastBody!.Operations as Array<Record<string, unknown>>;
      expect(operations).toHaveLength(1);
      expect(operations[0]).toEqual({ op: "replace", value: { active: false } });
    } finally {
      restoreFetch();
    }
  });
});
