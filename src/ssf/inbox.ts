import type { Inbox } from "./push";
import type { SetClaims } from "./set";

/** Each row is both the replay record and durable pending processing job.
 * Processing is intentionally separate; receiving an event has no side effect
 * on an account until a trusted, event-specific handler is implemented. */
export async function ensureSsfInboxTable(db: D1Database): Promise<void> {
  await db.prepare(`CREATE TABLE IF NOT EXISTS ssf_inbox (
    stream_id TEXT NOT NULL, issuer TEXT NOT NULL, jti TEXT NOT NULL,
    token_hash TEXT NOT NULL, token TEXT NOT NULL, state TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (stream_id, issuer, jti)
  )`).run();
  await db.prepare("CREATE INDEX IF NOT EXISTS ssf_inbox_pending_idx ON ssf_inbox (state, received_at)").run();
}

async function digest(token: string): Promise<string> {
  const value = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function createSsfInbox(db: D1Database): Inbox {
  return {
    async persist(streamId: string, claims: SetClaims, token: string) {
      if (!streamId || !claims.iss || !claims.jti) throw new Error("Invalid event identity");
      const hash = await digest(token);
      const result = await db.prepare(`INSERT INTO ssf_inbox
        (stream_id, issuer, jti, token_hash, token, state, received_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?) ON CONFLICT DO NOTHING`)
        .bind(streamId, claims.iss, claims.jti, hash, token, Math.floor(Date.now() / 1000)).run();
      if (!result.success || typeof result.meta?.changes !== "number") throw new Error("Inbox storage failed");
      if (result.meta.changes === 1) return "inserted";
      const existing = await db.prepare("SELECT token_hash FROM ssf_inbox WHERE stream_id = ? AND issuer = ? AND jti = ?")
        .bind(streamId, claims.iss, claims.jti).first<{ token_hash: string }>();
      if (!existing || existing.token_hash !== hash) throw new Error("Event identifier conflict");
      return "duplicate";
    },
  };
}

/** Prune processed rows past the retention window; pending rows are kept for
 * the (future) processing pipeline. */
export async function cleanupSsfInbox(db: D1Database, nowMs: number): Promise<void> {
  if (!Number.isSafeInteger(nowMs)) throw new Error("Invalid cleanup time");
  const horizon = Math.floor(nowMs / 1000) - 7 * 24 * 3600;
  await db.prepare("DELETE FROM ssf_inbox WHERE state != 'pending' AND received_at < ?").bind(horizon).run();
}
