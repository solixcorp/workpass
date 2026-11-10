import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { createSsfInbox, ensureSsfInboxTable } from "../../src/ssf/inbox";
import type { SetClaims } from "../../src/ssf/set";

test("inbox atomically queues events and rejects identifier collisions", async () => {
  const sqlite = new Database(":memory:");
  const db = { prepare(sql: string) {
    let values: (string | number)[] = [];
    return { bind(...args: (string | number)[]) { values = args; return this; },
      async run() { const result = sqlite.query(sql).run(...values); return { success: true, meta: { changes: result.changes } }; },
      async first() { return sqlite.query(sql).get(...values); } };
  } } as unknown as D1Database;
  try {
    await ensureSsfInboxTable(db);
    const inbox = createSsfInbox(db);
    const claims: SetClaims = { iss: "issuer", aud: "aud", jti: "event", iat: 1, sub_id: { format: "email" }, events: {} };
    expect(await Promise.all([inbox.persist("stream", claims, "signed-event"), inbox.persist("stream", claims, "signed-event")]))
      .toEqual(["inserted", "duplicate"]);
    await expect(inbox.persist("stream", claims, "different-event")).rejects.toThrow();
    expect(sqlite.query("SELECT state FROM ssf_inbox").get()).toEqual({ state: "pending" });
  } finally { sqlite.close(); }
});
