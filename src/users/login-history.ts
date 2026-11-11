import type { Env } from "../env";

interface Located {
  headers: { get(name: string): string | null };
  cf?: unknown;
}

/** Record a successful sign-in with where it came from. Never throws. */
export async function recordLogin(env: Env, request: Located, userId: string, method: string): Promise<string | null> {
  try {
    const cf = (request.cf ?? {}) as { country?: string; region?: string; city?: string };
    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO login_history (id, user_id, occurred_at, ip, user_agent, country, region, city, method)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      id, userId, new Date().toISOString(),
      (request.headers.get("cf-connecting-ip") ?? "").slice(0, 64) || null,
      (request.headers.get("user-agent") ?? "").slice(0, 512) || null,
      cf.country ?? null, cf.region ?? null, cf.city ?? null, method,
    ).run();
    return id;
  } catch {
    return null;
  }
}
