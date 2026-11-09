/** Replay protection for authenticated OAuth 1 requests. A unique database
 * constraint, rather than a read followed by a write, handles concurrent calls. */
export async function ensureOAuth1NonceTable(db: D1Database): Promise<void> {
  await db.prepare(`CREATE TABLE IF NOT EXISTS oauth1_nonce_claims (
    consumer_key TEXT NOT NULL,
    token TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (consumer_key, token, timestamp, nonce)
  )`).run();
  await db.prepare("CREATE INDEX IF NOT EXISTS oauth1_nonce_expiry_idx ON oauth1_nonce_claims (expires_at)").run();
}

export async function claimOAuth1Nonce(
  db: D1Database, consumerKey: string, token: string | undefined,
  timestamp: number, nonce: string, nowSeconds = Math.floor(Date.now() / 1000), maxClockSkew = 300,
): Promise<boolean> {
  if (!consumerKey || !nonce || !Number.isSafeInteger(timestamp) || !Number.isSafeInteger(nowSeconds) ||
      !Number.isSafeInteger(maxClockSkew) || maxClockSkew < 0 || Math.abs(nowSeconds - timestamp) > maxClockSkew) return false;
  // At timestamp + skew the timestamp is still valid, so keep the claim until
  // the following second. This remains true for future-dated requests.
  const result = await db.prepare(`INSERT INTO oauth1_nonce_claims (consumer_key, token, timestamp, nonce, expires_at)
    VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`)
    .bind(consumerKey, token ?? "", timestamp, nonce, timestamp + maxClockSkew + 1).run();
  if (!result.success || typeof result.meta?.changes !== "number") throw new Error("OAuth nonce storage failed");
  return result.meta.changes === 1;
}

export async function cleanupOAuth1Nonces(db: D1Database, nowSeconds: number): Promise<void> {
  if (!Number.isSafeInteger(nowSeconds)) throw new Error("Invalid cleanup time");
  await db.prepare("DELETE FROM oauth1_nonce_claims WHERE expires_at <= ?").bind(nowSeconds).run();
}
