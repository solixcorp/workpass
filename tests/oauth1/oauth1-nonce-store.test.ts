import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { claimOAuth1Nonce, cleanupOAuth1Nonces, ensureOAuth1NonceTable } from "../../src/oauth1/nonce-store";

test("nonce claims are atomic and retained through the inclusive clock window", async () => {
  const sqlite = new Database(":memory:");
  const db = { prepare(sql: string) {
    let values: (string | number)[] = [];
    return { bind(...args: (string | number)[]) { values = args; return this; },
      async run() { const result = sqlite.query(sql).run(...values); return { success: true, meta: { changes: result.changes } }; } };
  } } as unknown as D1Database;
  try {
    await ensureOAuth1NonceTable(db);
    const claim = () => claimOAuth1Nonce(db, "client", undefined, 1000, "nonce", 1000, 300);
    expect(await Promise.all([claim(), claim()])).toEqual([true, false]);
    await cleanupOAuth1Nonces(db, 1300);
    expect(await claimOAuth1Nonce(db, "client", undefined, 1000, "nonce", 1300, 300)).toBe(false);
    await cleanupOAuth1Nonces(db, 1301);
    expect(await claimOAuth1Nonce(db, "client", undefined, 1000, "nonce", 1301, 300)).toBe(false);
    expect(await claimOAuth1Nonce(db, "client", "token", 1301, "nonce", 1301, 300)).toBe(true);
  } finally { sqlite.close(); }
});
