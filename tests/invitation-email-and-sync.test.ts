import { describe, expect, test } from "bun:test";
import { ensureApplicationTables } from "../src/db/schema";
import {
  createAccount,
  createAccountInvitation,
  getAccountInvitation,
  markAccountInvitationDelivered,
} from "../src/accounts/store";
import {
  dispatchPendingScimOperations,
  scheduleScimAttributeSync,
  executeScimOperation,
  loadScimExecutorConfig,
} from "../src/scim/executor";
import { recordScimUserMapping } from "../src/scim/mappings";
import { sendTransactionEmail } from "../src/mail/send";
import type { Env } from "../src/env";
import { createTestD1 } from "./test-d1";

const RESEND_TOKEN = "resend-test-key";

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

describe("invitation email delivery", () => {
  test("a successful send records the recipient and time; re-delivery updates it", async () => {
    const env = ({ DB: createTestD1().db, AUTH_BASE_URL: "https://auth.example.test", RESEND_API_KEY: RESEND_TOKEN, INVITATION_EMAIL_FROM: "invites@example.test" }) as unknown as Env;
    await ensureApplicationTables(env);
    const account = (await createAccount(env, { name: "platform", description: "", creatorUserId: "u1" }))!;
    const invitation = await createAccountInvitation(env, { accountId: account.id, role: "member", ttlDays: 7, createdBy: "u1" });
    const { calls } = stubFetch(() => new Response(JSON.stringify({ id: "m1" }), { status: 200 }));
    try {
      await sendTransactionEmail(env, {
        to: "new-hire@example.test",
        subject: "invitation",
        text: `code ${invitation.token}`,
      });
      expect(calls).toHaveLength(1);
      expect(calls[0]!.url).toBe("https://api.resend.com/emails");
      expect((calls[0]!.body as Record<string, unknown>).from).toBe("invites@example.test");
      const body = calls[0]!.body as Record<string, string[]>;
      expect(body.to[0]).toBe("new-hire@example.test");
      expect(await markAccountInvitationDelivered(env, invitation.token, "new-hire@example.test")).toBe(true);
      const stored = await getAccountInvitation(env, invitation.token);
      expect(stored?.deliverTo).toBe("new-hire@example.test");
      expect(stored?.deliveredAt).not.toBeNull();
      // Re-delivery to another recipient updates the tracking fields.
      await sendTransactionEmail(env, { to: "other@example.test", subject: "invitation", text: "again" });
      await markAccountInvitationDelivered(env, invitation.token, "other@example.test");
      expect((await getAccountInvitation(env, invitation.token))!.deliverTo).toBe("other@example.test");
    } finally {
      restoreFetch();
    }
  });

  test("without a configured sender the delivery helper fails closed", async () => {
    const env = ({ DB: createTestD1().db, AUTH_BASE_URL: "https://auth.example.test" }) as unknown as Env;
    await ensureApplicationTables(env);
    await expect(
      sendTransactionEmail(env, { to: "x@example.test", subject: "s", text: "t" }),
    ).rejects.toThrow("Transactional email is not configured");
  });

  test("the webhook channel records the message instead of delivering", async () => {
    const env = ({
      DB: createTestD1().db,
      AUTH_BASE_URL: "https://auth.example.test",
      INVITATION_EMAIL_WEBHOOK_URL: "http://127.0.0.1:9999/invitations",
    }) as unknown as Env;
    await ensureApplicationTables(env);
    const { calls } = stubFetch(() => new Response(null, { status: 204 }));
    try {
      await sendTransactionEmail(env, { to: "dev@example.test", subject: "invitation", text: "code abc" });
      expect(calls).toHaveLength(1);
      expect(calls[0]!.url).toBe("http://127.0.0.1:9999/invitations");
      const body = calls[0]!.body as Record<string, unknown>;
      expect(body.to).toBe("dev@example.test");
      expect(body.subject).toBe("invitation");
      // The message is inlined for the mock receiver, including the sent time.
      expect(typeof body.sentAt).toBe("string");
    } finally {
      restoreFetch();
    }
  });
});

describe("pending SCIM operations", () => {
  test("the dispatcher drains queued ops through the same executor", async () => {
    const { db: DB, sqlite } = createTestD1();
    const env = {
      DB,
      ENABLE_SCIM_PROVISIONING: "true",
      SCIM_TARGET_ID: "target-1",
      SCIM_BASE_URL: "https://scim.example.test/v2",
      SCIM_BEARER_TOKEN: "target-token-0123456789abcdef",
      ENABLE_SCIM_ATTRIBUTE_RELEASE: "true",
      AUTH_BASE_URL: "https://auth.example.test",
    } as unknown as Env;
    await ensureApplicationTables(env);
    await sqlite.exec('CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY NOT NULL, email TEXT, name TEXT, username TEXT)');
    await env.DB.prepare(
      'INSERT INTO "user" (id, email, name) VALUES (\'u1\', \'u1@example.test\', \'User\')',
    ).run();
    // No attribute-release flag path issue: set attributes so the extension rides.
    const { setObjectAttributes } = await import("../src/objects/attributes");
    await setObjectAttributes(env, "user", "u1", { team: "core" }, "u1");
    await recordScimUserMapping(env, "target-1", "u1", "remote-1");
    const { createScimOperation } = await import("../src/scim/operations");
    expect(await createScimOperation(env, { targetId: "target-1", userId: "u1", operation: "update" })).not.toBeNull();
    // A scheduled sync finds an active op and does not enqueue a duplicate.
    expect(await scheduleScimAttributeSync(env, "u1")).toBe(false);

    const { calls } = stubFetch(() => new Response("{}", { status: 200 }));
    try {
      expect(await dispatchPendingScimOperations(env)).toBe(1);
      const operations = (calls[0]!.body as { Operations?: Array<Record<string, unknown>> }).Operations ?? [];
      expect(operations.some((operation) => operation.path === "urn:solixcorp:scim:1.0:CustomAttributes")).toBe(true);
      const drained = await env.DB.prepare("SELECT status FROM scim_operations").first<{ status: string }>();
      expect(drained?.status).toBe("succeeded");
    } finally {
      restoreFetch();
    }
  });

  test("an executor claim on a non-pending op fails without a remote call", async () => {
    const env = {
      DB: createTestD1().db,
      ENABLE_SCIM_PROVISIONING: "true",
      SCIM_TARGET_ID: "target-1",
      SCIM_BASE_URL: "https://scim.example.test/v2",
      SCIM_BEARER_TOKEN: "target-token-0123456789abcdef",
    } as unknown as Env;
    await ensureApplicationTables(env);
    expect(loadScimExecutorConfig(env)).not.toBeNull();
    const { calls } = stubFetch(() => new Response("{}", { status: 200 }));
    try {
      // Unknown operation ids resolve to nothing without touching the wire.
      expect(await executeScimOperation(env, loadScimExecutorConfig(env)!, "missing")).toBe(false);
      expect(calls).toHaveLength(0);
    } finally {
      restoreFetch();
    }
  });
});
