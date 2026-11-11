import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { describeDevice } from "../users/device";
import { auditStandaloneOperation } from "../audit/store";
import { revokeTrustedDevices } from "./trusted-device-store";
import { requireSameOrigin } from "./authorization";
import {
  consumeFingerprintLookupBudget,
  digestVisitorId,
  fingerprintMode,
  verifyFingerprintEvent,
} from "./fingerprint";

export const trustedDeviceRoutes = new Hono<{ Bindings: Env }>();

trustedDeviceRoutes.get("/sessions/overview", async (context) => {
  context.header("Cache-Control", "no-store");
  const auth = createAuth(context.env);
  const headers = context.req.raw.headers;
  const session = await auth.api.getSession({ headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  const sessions = await auth.api.listSessions({ headers });
  const history = await context.env.DB.prepare(
    `SELECT ip, user_agent, city, region, country FROM login_history
     WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 100`,
  ).bind(session.user.id).all<{
    ip: string | null;
    user_agent: string | null;
    city: string | null;
    region: string | null;
    country: string | null;
  }>();

  return context.json({ sessions: sessions.map((item) => {
    const matches = item.ipAddress ? history.results.filter((row) => row.ip === item.ipAddress) : [];
    const match = (item.userAgent ? matches.find((row) => row.user_agent === item.userAgent) : undefined) ?? matches[0];
    return {
      token: item.token,
      id: item.id,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt ?? null,
      expiresAt: item.expiresAt ?? null,
      current: item.token === session.session.token,
      ipAddress: item.ipAddress ?? null,
      userAgent: item.userAgent ?? null,
      label: describeDevice(item.userAgent ?? match?.user_agent).label,
      location: match ? { city: match.city, region: match.region, country: match.country } : null,
    };
  }) });
});

trustedDeviceRoutes.get("/trusted-devices", async (context) => {
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  const rows = await context.env.DB.prepare(
    `SELECT id, label, created_at, last_seen_at, expires_at, revoked_at
     FROM trusted_devices WHERE user_id = ? ORDER BY created_at DESC`,
  )
    .bind(session.user.id)
    .all<{
      id: string;
      label: string;
      created_at: string;
      last_seen_at: string;
      expires_at: string;
      revoked_at: string | null;
    }>();
  return context.json({ devices: rows.results });
});

trustedDeviceRoutes.post("/trusted-devices", async (context) => {
  const originFailure = requireSameOrigin(context);
  if (originFailure) return originFailure;
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "Invalid request" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return context.json({ error: "Invalid request" }, 400);
  }
  const { event_id: eventId, password, label: requestedLabel } = body as Record<string, unknown>;
  if (
    typeof eventId !== "string" ||
    typeof password !== "string" ||
    (requestedLabel !== undefined && typeof requestedLabel !== "string")
  ) {
    return context.json({ error: "event_id and password are required" }, 400);
  }
  if (!await hasCredentialPassword(context.env, session.user.id)) {
    return context.json({ error: "Password confirmation is unavailable for this account" }, 409);
  }
  const label = (requestedLabel ?? "Trusted device").trim().slice(0, 80) || "Trusted device";

  return auditStandaloneOperation(
    context.env,
    "authentication.trusted_device.enroll",
    "/api/security/trusted-devices",
    async () => {
      const mode = fingerprintMode(context.env);
      if (mode === "disabled") {
        return {
          response: Response.json({ error: "Device risk policy is disabled" }, { status: 404 }),
          actorUserId: session.user.id,
        };
      }

      let withinBudget = false;
      try {
        withinBudget = await consumeFingerprintLookupBudget({
          env: context.env,
          request: context.req.raw,
          limit: 10,
        });
      } catch {
        withinBudget = false;
      }
      if (!withinBudget) {
        return {
          response: Response.json({ error: "Device verification failed" }, { status: 429 }),
          actorUserId: session.user.id,
        };
      }

      const verified = await verifyFingerprintEvent({
        env: context.env,
        request: context.req.raw,
        eventId,
      });
      if (!verified.event || verified.error) {
        return {
          response: Response.json({ error: "Device verification failed" }, { status: 403 }),
          actorUserId: session.user.id,
        };
      }
      const event = verified.event;
      const minimumConfidence = Number(context.env.FINGERPRINT_MIN_CONFIDENCE ?? "0.7");
      const suspectThreshold = context.env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD
        ? Number(context.env.FINGERPRINT_SUSPECT_SCORE_THRESHOLD)
        : null;
      if (
        event.confidence < minimumConfidence ||
        (event.bot !== undefined && event.bot !== "not_detected") ||
        event.tampering ||
        event.mitmAttack ||
        event.locationSpoofing ||
        (suspectThreshold !== null &&
          event.suspectScore !== undefined &&
          event.suspectScore >= suspectThreshold)
      ) {
        return {
          response: Response.json({ error: "Device verification failed" }, { status: 403 }),
          actorUserId: session.user.id,
        };
      }

      try {
        await auth.api.verifyPassword({
          body: { password },
          headers: context.req.raw.headers,
        });
      } catch {
        return {
          response: Response.json({ error: "Device verification failed" }, { status: 403 }),
          actorUserId: session.user.id,
        };
      }

      const visitorDigest = await digestVisitorId(context.env, event.visitorId);
      const now = new Date();
      const createdAt = now.toISOString();
      const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
      const deviceId = crypto.randomUUID();
      const claimToken = crypto.randomUUID();
      const consumedAt = createdAt;
      const enrollment = await context.env.DB.batch([
        context.env.DB.prepare(
          "DELETE FROM fingerprint_event_claims WHERE expires_at < ?",
        ).bind(createdAt),
        context.env.DB.prepare(
          `INSERT OR IGNORE INTO fingerprint_event_claims
            (event_id, user_id, context, claimed_at, expires_at, consumed_at, claim_token)
           VALUES (?, ?, 'trusted_device_enrollment', ?, ?, NULL, ?)`,
        ).bind(
          event.eventId,
          session.user.id,
          createdAt,
          new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
          claimToken,
        ),
        context.env.DB.prepare(
          `UPDATE fingerprint_event_claims SET consumed_at = ?
           WHERE event_id = ? AND user_id = ? AND claim_token = ? AND consumed_at IS NULL`,
        ).bind(consumedAt, event.eventId, session.user.id, claimToken),
        context.env.DB.prepare(`INSERT INTO trusted_devices
          (id, user_id, visitor_digest, label, created_at, last_seen_at, expires_at, revoked_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, NULL
         WHERE EXISTS (
           SELECT 1 FROM fingerprint_event_claims
           WHERE event_id = ? AND user_id = ? AND claim_token = ? AND consumed_at = ?
         )
         ON CONFLICT(user_id, visitor_digest) DO UPDATE SET
           id = excluded.id,
           label = excluded.label,
           created_at = excluded.created_at,
           last_seen_at = excluded.last_seen_at,
           expires_at = excluded.expires_at,
           revoked_at = NULL`).bind(
          deviceId,
          session.user.id,
          visitorDigest,
          label,
          createdAt,
          createdAt,
          expiresAt,
          event.eventId,
          session.user.id,
          claimToken,
          consumedAt,
        ),
      ]);

      if (enrollment[1]?.meta.changes !== 1 || enrollment[2]?.meta.changes !== 1 || enrollment[3]?.meta.changes !== 1) {
        return {
          response: Response.json({ error: "Device verification failed" }, { status: 403 }),
          actorUserId: session.user.id,
        };
      }

      return {
        response: Response.json(
          { device: { id: deviceId, label, createdAt, expiresAt } },
          { status: 201 },
        ),
        actorUserId: session.user.id,
        targetUserId: session.user.id,
      };
    },
  );
});

trustedDeviceRoutes.delete("/trusted-devices", async (context) => {
  const originFailure = requireSameOrigin(context);
  if (originFailure) return originFailure;
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "Invalid request" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      typeof (body as { password?: unknown }).password !== "string") {
    return context.json({ error: "password is required" }, 400);
  }
  const password = (body as { password: string }).password;
  if (!await hasCredentialPassword(context.env, session.user.id)) {
    return context.json({ error: "Password confirmation is unavailable for this account" }, 409);
  }

  return revokeDevices(context.env, auth, context.req.raw, session.user.id, null, password);
});

trustedDeviceRoutes.delete("/trusted-devices/:deviceId", async (context) => {
  const originFailure = requireSameOrigin(context);
  if (originFailure) return originFailure;
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);

  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    return context.json({ error: "Invalid request" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      typeof (body as { password?: unknown }).password !== "string") {
    return context.json({ error: "password is required" }, 400);
  }
  const password = (body as { password: string }).password;
  if (!await hasCredentialPassword(context.env, session.user.id)) {
    return context.json({ error: "Password confirmation is unavailable for this account" }, 409);
  }

  return revokeDevices(
    context.env,
    auth,
    context.req.raw,
    session.user.id,
    context.req.param("deviceId"),
    password,
  );
});

trustedDeviceRoutes.delete("/trusted-devices/user/:userId", async (context) => {
  const originFailure = requireSameOrigin(context);
  if (originFailure) return originFailure;
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const role = (session.user as typeof session.user & { role?: unknown }).role;
  if (!(typeof role === "string" && role.split(",").includes("admin"))) {
    return context.json({ error: "Forbidden" }, 403);
  }
  const userId = context.req.param("userId");
  return auditStandaloneOperation(
    context.env,
    "identity.user.trusted_devices.revoke",
    "/api/security/trusted-devices/user/:userId",
    async () => {
      const revoked = await revokeTrustedDevices(context.env, userId);
      return {
        response: Response.json({ status: true, revoked }),
        actorUserId: session.user.id,
        targetUserId: userId,
      };
    },
  );
});

async function hasCredentialPassword(env: Env, userId: string): Promise<boolean> {
  const account = await env.DB.prepare(
    `SELECT id FROM account
     WHERE userId = ? AND providerId = 'credential' AND password IS NOT NULL
     LIMIT 1`,
  )
    .bind(userId)
    .first<{ id: string }>();
  return account !== null;
}

async function revokeDevices(
  env: Env,
  auth: ReturnType<typeof createAuth>,
  request: Request,
  userId: string,
  deviceId: string | null,
  password: string,
): Promise<Response> {
  return auditStandaloneOperation(
    env,
    "authentication.trusted_device.revoke",
    "/api/security/trusted-devices",
    async () => {
      try {
        await auth.api.verifyPassword({ body: { password }, headers: request.headers });
      } catch {
        return {
          response: Response.json({ error: "Device verification failed" }, { status: 403 }),
          actorUserId: userId,
        };
      }

      const now = new Date().toISOString();
      const result = deviceId
        ? await env.DB.prepare(
            `UPDATE trusted_devices SET revoked_at = ?
             WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
          )
            .bind(now, deviceId, userId)
            .run()
        : { meta: { changes: await revokeTrustedDevices(env, userId) } };

      return {
        response: Response.json({ status: true, revoked: result.meta.changes }),
        actorUserId: userId,
        targetUserId: userId,
      };
    },
  );
}
