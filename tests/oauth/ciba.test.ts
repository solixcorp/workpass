import { describe, expect, test } from "bun:test";
import {
  cleanupCibaRequests, consumeCibaRequest, createCibaRequest, decideCibaRequest,
  listPendingCibaRequests, loadCibaRequest, normalizeBindingMessage, sha256Hex,
} from "../../src/oauth/ciba";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

async function env(): Promise<Env> {
  const testD1 = createTestD1();
  const e = { DB: testD1.db, AUTH_BASE_URL: "https://auth.example.test" } as unknown as Env;
  const { ensureApplicationTables } = await import("../../src/db/schema");
  await ensureApplicationTables(e);
  return e;
}

describe("ciba request store", () => {
  test("roundtrips the request and sanitizes the binding message", async () => {
    expect(normalizeBindingMessage("Transfer €10\u0007 to ops")).toBe("Transfer €10 to ops");
    expect(normalizeBindingMessage("x".repeat(300)).length).toBe(128);
    const e = await env();
    const issued = await createCibaRequest(e, {
      clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "login from CLI",
    });
    expect(issued.expiresInSeconds).toBe(300);
    const request = await loadCibaRequest(e, issued.authReqId);
    expect(request?.status).toBe("pending");
    expect(request?.bindingMessage).toBe("login from CLI");
    expect(request?.userId).toBe("u1");
    // The auth_req_id is stored hashed: a forged value resolves to nothing.
    expect(await loadCibaRequest(e, "forged-auth-req-id-value")).toBeNull();
  });

  test("approves once, consumes once; denied requests leave the pending list", async () => {
    const e = await env();
    const first = await createCibaRequest(e, { clientId: "cli-1", userId: "u1", scopes: ["openid", "email"], bindingMessage: "" });
    const pending = await listPendingCibaRequests(e, "u1");
    // The user surface only ever sees the hashed request id.
    expect(pending.map((request) => request.id)).toEqual([await sha256Hex(first.authReqId)]);
    expect(await decideCibaRequest(e, pending[0]!.id, "u1", true, "sess-1")).toBe(true);
    expect((await listPendingCibaRequests(e, "u1")).length).toBe(0);
    expect(await consumeCibaRequest(e, first.authReqId)).toBe(true);
    expect(await consumeCibaRequest(e, first.authReqId)).toBe(false);
    const denied = await createCibaRequest(e, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "" });
    expect(await decideCibaRequest(e, await sha256Hex(denied.authReqId), "u1", false, "sess-1")).toBe(true);
    expect(await consumeCibaRequest(e, denied.authReqId)).toBe(false);
    // Only the owning user decides; a decided row cannot be re-decided.
    expect(await decideCibaRequest(e, await sha256Hex(denied.authReqId), "u2", true, "sess-2")).toBe(false);
    expect(await decideCibaRequest(e, await sha256Hex(denied.authReqId), "u1", true, "sess-1")).toBe(false);
  });

  test("caps pending requests per user and frees the slot after a decision", async () => {
    const e = await env();
    for (let index = 0; index < 5; index += 1) {
      await createCibaRequest(e, { clientId: `cli-${index}`, userId: "u1", scopes: ["openid"], bindingMessage: "" });
    }
    await expect(createCibaRequest(e, { clientId: "cli-x", userId: "u1", scopes: ["openid"], bindingMessage: "" }))
      .rejects.toThrow("user_cap_reached");
    const other = await createCibaRequest(e, { clientId: "cli-x", userId: "u2", scopes: ["openid"], bindingMessage: "" });
    expect(await decideCibaRequest(e, await sha256Hex(other.authReqId), "u2", true, "sess-2")).toBe(true);
    // Denying one frees u1's slot.
    const first = (await listPendingCibaRequests(e, "u1"))[0]!;
    expect(await decideCibaRequest(e, first.id, "u1", false, "sess-1")).toBe(true);
    await expect(createCibaRequest(e, { clientId: "cli-x", userId: "u1", scopes: ["openid"], bindingMessage: "" }))
      .resolves.toBeDefined();
  });

  test("expired and decided requests are cleaned up", async () => {
    const e = await env();
    const now = Date.now();
    const expired = await createCibaRequest(e, { clientId: "cli-1", userId: "u1", scopes: ["openid"], bindingMessage: "" });
    await e.DB.prepare("UPDATE oauth_ciba_requests SET expires_at = ? WHERE auth_req_id_hash = ?")
      .bind(now - 1000, await sha256Hex(expired.authReqId)).run();
    const denied = await createCibaRequest(e, { clientId: "cli-1", userId: "u2", scopes: ["openid"], bindingMessage: "" });
    await decideCibaRequest(e, await sha256Hex(denied.authReqId), "u2", false, "sess-2");
    expect(await cleanupCibaRequests(e, new Date(now))).toBe(2);
    const remaining = await e.DB.prepare("SELECT COUNT(*) AS c FROM oauth_ciba_requests").first<{ c: number }>();
    expect(remaining?.c).toBe(0);
  });
});
