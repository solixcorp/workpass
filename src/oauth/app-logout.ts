import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { isSafeBackchannelUri } from "./backchannel-uri";

export type LogoutStatus = "sent" | "failed" | "not_supported";
export type LogoutApp = { clientId: string; applicationName: string; status: LogoutStatus; httpStatus?: number };
type TokenRow = { clientId: string; createdAt: string | number | null; sessionId: string | null };
type Client = { clientId: string; name: string | null; backchannelLogoutUri: string | null; backchannelLogoutSessionRequired: number | null; slug: string | null; applicationName: string };

// better-auth uses epoch milliseconds, although older installations can have
// ISO timestamps. Filter in JS so both representations work consistently.
function time(value: string | number | null): number {
  if (value === null) return 0;
  if (typeof value === "number" || /^\d+$/.test(value)) return Number(value);
  return Date.parse(value) || 0;
}

export async function appSessionSnapshot(env: Env, userId: string) {
  const tokens = await env.DB.prepare(`SELECT clientId, createdAt, sessionId, expiresAt FROM "oauthAccessToken" WHERE userId = ? AND revoked IS NULL
    UNION ALL SELECT clientId, createdAt, sessionId, expiresAt FROM "oauthRefreshToken" WHERE userId = ? AND revoked IS NULL`)
    .bind(userId, userId).all<TokenRow & { expiresAt: string | number }>();
  const active = tokens.results.filter((row) => time(row.expiresAt) > Date.now());
  const clients = await env.DB.prepare(`SELECT c.clientId, c.name, c.backchannelLogoutUri, c.backchannelLogoutSessionRequired,
    (SELECT slug FROM applications a WHERE a.protocol = 'oidc' AND a.binding = c.clientId ORDER BY slug LIMIT 1) AS slug,
    COALESCE((SELECT name FROM applications a WHERE a.protocol = 'oidc' AND a.binding = c.clientId ORDER BY slug LIMIT 1), c.name, c.clientId) AS applicationName
    FROM "oauthClient" c`).all<Client>();
  return { active, clients: clients.results };
}

export function presentSessions(snapshot: Awaited<ReturnType<typeof appSessionSnapshot>>) {
  return snapshot.clients.flatMap((client) => {
    const tokens = snapshot.active.filter((t) => t.clientId === client.clientId);
    if (!tokens.length) return [];
    const last = Math.max(...tokens.map((t) => time(t.createdAt)));
    return [{ clientId: client.clientId, slug: client.slug, applicationName: client.applicationName,
      activeTokens: tokens.length, lastIssuedAt: last ? new Date(last).toISOString() : null,
      backchannelLogout: !!client.backchannelLogoutUri }];
  });
}

export async function logoutUserFromApps(env: Env, userId: string, options: {
  clientId?: string; reason: string; forgetConsent?: boolean;
  snapshot?: Awaited<ReturnType<typeof appSessionSnapshot>>;
}): Promise<{ revokedTokens: number; apps: LogoutApp[]; error?: true }> {
  try {
    const snapshot = options.snapshot ?? await appSessionSnapshot(env, userId);
    const filter = options.clientId ? " AND clientId = ?" : "";
    const args = options.clientId ? [userId, options.clientId] : [userId];
    const now = Date.now();
    const statements = [
      env.DB.prepare(`UPDATE "oauthAccessToken" SET revoked = ? WHERE userId = ? AND revoked IS NULL${filter}`).bind(now, ...args),
      env.DB.prepare(`UPDATE "oauthRefreshToken" SET revoked = ?, rotationReplayResponse = NULL, rotationReplayExpiresAt = NULL WHERE userId = ? AND revoked IS NULL${filter}`).bind(now, ...args),
    ];
    if (options.forgetConsent) statements.push(env.DB.prepare(`DELETE FROM "oauthConsent" WHERE userId = ?${filter}`).bind(...args));
    const results = await env.DB.batch(statements);
    const revokedTokens = (results[0]?.meta.changes ?? 0) + (results[1]?.meta.changes ?? 0);
    const clients = snapshot.clients.filter((c) => (!options.clientId || c.clientId === options.clientId) &&
      (snapshot.active.some((t) => t.clientId === c.clientId) || (options.clientId && options.forgetConsent)));
    const apps = await Promise.all(clients.map(async (client): Promise<LogoutApp> => {
      const base = { clientId: client.clientId, applicationName: client.applicationName };
      if (!client.backchannelLogoutUri) return { ...base, status: "not_supported" };
      try {
        // The DB trigger enforces approval, but recheck immediately before use.
        if (!isSafeBackchannelUri(client.backchannelLogoutUri) || !await env.DB.prepare("SELECT 1 FROM oidc_logout_uri_approvals WHERE uri = ?").bind(client.backchannelLogoutUri).first()) return { ...base, status: "failed" };
        const clientTokens = snapshot.active.filter((t) => t.clientId === client.clientId);
        const sids = [...new Set(clientTokens.map((t) => t.sessionId).filter((s): s is string => !!s))];
        if (client.backchannelLogoutSessionRequired && (!sids.length || clientTokens.some((t) => !t.sessionId))) return { ...base, status: "failed" };
        const targets: (string | undefined)[] = client.backchannelLogoutSessionRequired ? sids : [undefined];
        let status = 200;
        for (const sid of targets) {
          const iat = Math.floor(Date.now() / 1000);
          const signed = await createAuth(env).api.signJWT({ body: { payload: {
            iss: `${new URL(env.AUTH_BASE_URL).origin}/api/auth`, aud: client.clientId, sub: userId,
            iat, exp: iat + 300, jti: crypto.randomUUID(),
            events: { "http://schemas.openid.net/event/backchannel-logout": {} }, ...(sid ? { sid } : {}),
          } } });
          const response = await fetch(client.backchannelLogoutUri, { method: "POST", redirect: "error",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ logout_token: signed.token }), signal: AbortSignal.timeout(5000) });
          status = response.status;
          if (!response.ok) return { ...base, status: "failed", httpStatus: status };
        }
        return { ...base, status: "sent", httpStatus: status };
      } catch { return { ...base, status: "failed" }; }
    }));
    return { revokedTokens, apps };
  } catch (error) {
    console.error("App logout failed", { reason: options.reason, name: error instanceof Error ? error.name : "UnknownError" });
    return { revokedTokens: 0, apps: [], error: true };
  }
}
