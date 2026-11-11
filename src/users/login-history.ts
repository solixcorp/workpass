import type { Env } from "../env";
import { describeDevice } from "./device";
import { notifySecurity } from "./notifications";

interface Located {
  headers: { get(name: string): string | null };
  cf?: unknown;
}

export async function hashSessionToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Record a successful sign-in with where it came from. Never throws. */
export async function recordLogin(env: Env, request: Located, userId: string, method: string, sessionToken?: string): Promise<string | null> {
  try {
    const cf = (request.cf ?? {}) as { country?: string; region?: string; city?: string };
    const id = crypto.randomUUID();
    try {
      const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
      const previous = await env.DB.prepare(
        `SELECT user_agent, country, occurred_at FROM login_history WHERE user_id = ? AND
         (occurred_at >= ? OR occurred_at = (SELECT MIN(occurred_at) FROM login_history WHERE user_id = ?))`,
      ).bind(userId, cutoff, userId).all<{ user_agent: string | null; country: string | null; occurred_at: string }>();
      const label = describeDevice(request.headers.get("user-agent")).label;
      const known = previous.results.some((row) => row.occurred_at >= cutoff && row.country === (cf.country ?? null) && describeDevice(row.user_agent).label === label);
      if (previous.results.length && !known) {
        await notifySecurity(env, userId, { kind: "security_new_device", title: "새 기기에서 로그인했습니다", body: `${label} · ${cf.country ?? "위치 알 수 없음"}`, link: "/activity" });
      }
    } catch {
      // A history lookup must not prevent recording the sign-in.
    }
    await env.DB.prepare(
      `INSERT INTO login_history (id, user_id, occurred_at, ip, user_agent, country, region, city, method, session_token_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      id, userId, new Date().toISOString(),
      (request.headers.get("cf-connecting-ip") ?? "").slice(0, 64) || null,
      (request.headers.get("user-agent") ?? "").slice(0, 512) || null,
      cf.country ?? null, cf.region ?? null, cf.city ?? null, method, sessionToken ? await hashSessionToken(sessionToken) : null,
    ).run();
    return id;
  } catch {
    return null;
  }
}
