import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { ensureApplicationTables } from "../src/db/schema";
import { upsertSsfRecipient } from "../src/ssf/dispatch";
import { emitAttributeChangedEvent, ATTRIBUTE_CHANGED_EVENT_TYPE } from "../src/ssf/attribute-events";
import { devMockRoutes } from "../src/dev/mock-mail";
import { sendTransactionEmail } from "../src/mail/send";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

function stubFetch(handler: (url: string, body: unknown) => Response): { calls: Array<{ url: string; body: unknown }> } {
  const calls: Array<{ url: string; body: unknown }> = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ url, body });
    return handler(url, body);
  }) as typeof fetch;
  (globalThis.fetch as { __restore?: () => void }).__restore = () => {
    globalThis.fetch = original;
  };
  return { calls };
}

function restoreFetch(): void {
  (globalThis.fetch as { __restore?: () => void }).__restore?.();
}

describe("SSF attribute-change event", () => {
  /** Capture the pushed SET: the body is a compact JWT, not JSON. */
  function stubSetFetch(): { pushes: Array<{ url: string; token: string }> } {
    const pushes: Array<{ url: string; token: string }> = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      pushes.push({ url: String(input), token: String(init?.body ?? "") });
      return new Response(null, { status: 202 });
    }) as typeof fetch;
    (globalThis.fetch as { __restore?: () => void }).__restore = () => {
      globalThis.fetch = original;
    };
    return { pushes };
  }

  function decodeSetPayload(token: string): Record<string, unknown> {
    const middle = token.split(".")[1]!;
    const padded = middle.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(middle.length / 4) * 4, "=");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  }

  test("emits a signed SET only to recipients subscribed to the URN", async () => {
    const testD1 = createTestD1();
    const env = {
      DB: testD1.db,
      AUTH_BASE_URL: "https://auth.example.test",
      ENABLE_SSF_SENDER: "true",
      // The SET signature private key is sealed at rest; this test key is the
      // base64 of 32 bytes.
      AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    } as unknown as Env;
    await upsertSsfRecipient(env, {
      id: "r-subscribed", audience: "aud-a", endpoint: "https://recipient.test/set",
      eventTypes: [ATTRIBUTE_CHANGED_EVENT_TYPE, "https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
    });
    await upsertSsfRecipient(env, {
      id: "r-other", audience: "aud-b", endpoint: "https://other.test/set",
      eventTypes: ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
    });
    const { pushes } = stubSetFetch();
    try {
      const sent = await emitAttributeChangedEvent(env, {
        userId: "u1", objectType: "user", objectId: "u1", changedKeys: ["team", "level"],
      });
      // Exactly the subscribed recipient got one push.
      expect(sent).toBe(1);
      expect(pushes).toHaveLength(1);
      expect(pushes[0]!.url).toBe("https://recipient.test/set");
      const claims = decodeSetPayload(pushes[0]!.token);
      expect(claims.aud).toBe("aud-a");
      expect(Object.keys(claims.events as Record<string, unknown>)).toEqual([ATTRIBUTE_CHANGED_EVENT_TYPE]);
      const event = (claims.events as Record<string, Record<string, unknown>>)[ATTRIBUTE_CHANGED_EVENT_TYPE]!;
      expect(event).toEqual({ object_type: "user", object_id: "u1", changed_keys: ["team", "level"] });
      expect(claims.sub_id).toEqual({ user: { user_id: "u1" } });
    } finally {
      restoreFetch();
    }
  });

  test("no subscribers, or the sender disabled, means zero emissions", async () => {
    const { db } = createTestD1();
    const env = { DB: db, AUTH_BASE_URL: "https://auth.example.test", ENABLE_SSF_SENDER: "true" } as unknown as Env;
    expect(await emitAttributeChangedEvent(env, { userId: "u1", objectType: "user", objectId: "u1", changedKeys: [] })).toBe(0);
    const disabled = { ...env, ENABLE_SSF_SENDER: "false" } as Env;
    expect(await emitAttributeChangedEvent(disabled, { userId: "u1", objectType: "user", objectId: "u1", changedKeys: [] })).toBe(0);
  });
});

describe("built-in dev mock mailbox", () => {
  function mockApp(env: Env): Hono<{ Bindings: Env }> {
    const hono = new Hono<{ Bindings: Env }>();
    hono.route("/", devMockRoutes);
    return hono;
  }

  test("fail-closed: 404 without ENABLE_DEV_MOCKS", async () => {
    const { db } = createTestD1();
    const env = { DB: db } as unknown as Env;
    const hono = mockApp(env);
    const response = await hono.request("/dev/mocks/invitation-email", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: "a@b.test", subject: "s", text: "t" }),
    }, env);
    expect(response.status).toBe(404);
  });

  test("records invitation emails and lists them newest-first", async () => {
    const { db } = createTestD1();
    const env = { DB: db, ENABLE_DEV_MOCKS: "true" } as unknown as Env;
    const hono = mockApp(env);
    const recorded = await hono.request("/dev/mocks/invitation-email", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: "a@b.test", subject: "invitation", text: "code abc-1 sentAt inline" }),
    }, env);
    expect(recorded.status).toBe(201);
    // The send helper can point at the built-in route like any webhook.
    const { calls } = stubFetch(() => new Response(null, { status: 204 }));
    try {
      await sendTransactionEmail(
        { ...env, INVITATION_EMAIL_WEBHOOK_URL: "http://localhost/dev/mocks/invitation-email" } as unknown as Env,
        { to: "c@d.test", subject: "invitation2", text: "code abc-2" },
      );
      // Deliver through the worker in the same manner the webhook does.
      const viaWorker = await hono.request(`/dev/mocks/invitation-email`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(calls[calls.length - 1]!.body),
      }, env);
      expect(viaWorker.status).toBe(201);
    } finally {
      restoreFetch();
    }
    const listed = await hono.request("/dev/mocks/invitation-email", {}, env);
    const body = await listed.json() as { messages: Array<{ to: string; subject: string | null; text: string | null }> };
    expect(body.messages).toHaveLength(2);
    expect(body.messages[0]!.subject).toBe("invitation2");
    expect(body.messages[1]!.text).toContain("abc-1");
  });

  test("oversized or malformed recordings are rejected", async () => {
    const { db } = createTestD1();
    const env = { DB: db, ENABLE_DEV_MOCKS: "true" } as unknown as Env;
    const hono = mockApp(env);
    const oversized = await hono.request("/dev/mocks/invitation-email", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ to: "a@b.test", text: "x".repeat(4097) }),
    }, env);
    expect(oversized.status).toBe(400);
    const malformed = await hono.request("/dev/mocks/invitation-email", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{not json",
    }, env);
    expect(malformed.status).toBe(400);
  });
});
