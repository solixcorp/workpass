import { describe, expect, test } from "bun:test";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";
import { claimOAuth1Nonce } from "../../src/oauth1/nonce-store";
import { approveTemporaryToken, cleanupOAuth1Temporaries, consumeTemporaryToken, issueAccessToken, issueTemporaryToken, loadTemporaryToken, OAUTH1_TEMPORARY_TTL_SECONDS, rejectTemporaryToken, resolveOAuth1AccessToken, revokeOAuth1UserTokens } from "../../src/oauth1/store";

describe("OAuth 1 credential storage", () => {
  const { db, sqlite } = createTestD1();
  const env = { DB: db, AEAD_SEALING_KEY: btoa("oauth1-test-sealing-key-32-bytes") } as Env;

  test("temporary expiry uses seconds and handles legacy milliseconds", async () => {
    const issued = await issueTemporaryToken(env, "client", "oob");
    const row = sqlite.query("SELECT created_at, expires_at FROM oauth1_temporary_tokens WHERE token = ?").get(issued.token) as { created_at: number; expires_at: number };
    expect(row.expires_at - row.created_at).toBe(OAUTH1_TEMPORARY_TTL_SECONDS);
    expect(issued.expiresAt).toBe(row.expires_at);
    expect((await loadTemporaryToken(env, issued.token))?.expired).toBe(false);
    const now = Math.floor(Date.now() / 1000);
    sqlite.query("UPDATE oauth1_temporary_tokens SET expires_at = ? WHERE token = ?").run(now, issued.token);
    expect((await loadTemporaryToken(env, issued.token))?.expired).toBe(true);
    expect(await approveTemporaryToken(env, issued.token, "user")).toBe(false);
    sqlite.query("UPDATE oauth1_temporary_tokens SET expires_at = ? WHERE token = ?").run((now + 100) * 1000, issued.token);
    expect((await loadTemporaryToken(env, issued.token))?.expiresAt).toBe(now + 100);
    expect((await loadTemporaryToken(env, issued.token))?.expired).toBe(false);
    sqlite.query("UPDATE oauth1_temporary_tokens SET expires_at = ? WHERE token = ?").run((now - 1) * 1000, issued.token);
    expect((await loadTemporaryToken(env, issued.token))?.secret).toBeNull();
    await cleanupOAuth1Temporaries(env, now * 1000);
    expect(await loadTemporaryToken(env, issued.token)).toBeNull();
  });

  test("cleanup removes expired nonces and retains fresh claims", async () => {
    const now = Math.floor(Date.now() / 1000);
    await claimOAuth1Nonce(db, "client", undefined, now - 300, "old", now, 300);
    await claimOAuth1Nonce(db, "client", undefined, now, "fresh", now, 300);
    await cleanupOAuth1Temporaries(env, (now + 2) * 1000);
    const rows = sqlite.query("SELECT nonce FROM oauth1_nonce_claims ORDER BY nonce").all() as { nonce: string }[];
    expect(rows.map((row) => row.nonce)).toEqual(["fresh"]);
  });

  test("offboarding removes only the user's access and pending tokens and returns the count", async () => {
    const a = await issueAccessToken(env, "client", "user-a");
    const b = await issueAccessToken(env, "client", "user-b");
    const pending = await issueTemporaryToken(env, "client", "oob");
    const other = await issueTemporaryToken(env, "client", "oob");
    await approveTemporaryToken(env, pending.token, "user-a");
    await approveTemporaryToken(env, other.token, "user-b");
    expect(await revokeOAuth1UserTokens(env, "user-a")).toBe(2);
    expect(await resolveOAuth1AccessToken(env, a.token)).toBeNull();
    expect(await loadTemporaryToken(env, pending.token)).toBeNull();
    expect(await resolveOAuth1AccessToken(env, b.token)).not.toBeNull();
    expect(await loadTemporaryToken(env, other.token)).not.toBeNull();
    expect(await revokeOAuth1UserTokens(env, "user-a")).toBe(0);
  });

  test("expired approved credentials cannot be consumed", async () => {
    const token = await issueTemporaryToken(env, "client", "oob");
    await approveTemporaryToken(env, token.token, "user");
    sqlite.query("UPDATE oauth1_temporary_tokens SET expires_at = ? WHERE token = ?").run(Math.floor(Date.now() / 1000), token.token);
    expect(await consumeTemporaryToken(env, token.token, "client", "user", token.verifier)).toBe(false);
  });

  test("approval and denial compete atomically", async () => {
    const token = await issueTemporaryToken(env, "client", "oob");
    const outcomes = await Promise.all([approveTemporaryToken(env, token.token, "user"), rejectTemporaryToken(env, token.token)]);
    expect(outcomes.filter(Boolean)).toHaveLength(1);
  });
});
