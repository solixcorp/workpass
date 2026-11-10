/**
 * The reputation policy family (docs/design/authentik-policies.md): login
 * outcomes move a client-IP / username score toward or away from the
 * configured threshold and the policy fails when a relevant score is at or
 * below it. Scores decay by expiry rather than by half-life, matching the
 * authentik settings-driven expiry behavior.
 */

import type { Env } from "../env";

export const REPUTATION_SCORE_LIMIT = 100;

export interface ReputationConfig {
  /** `ip`, `username` or `both`. */
  check: "ip" | "username" | "both";
  threshold: number;
}

export function validateReputationConfig(config: unknown): ReputationConfig {
  const value = (config ?? {}) as Record<string, unknown>;
  const check = value.check === "username" || value.check === "both" ? value.check : value.check === "ip" ? "ip" : null;
  if (check === null) throw new Error("reputation config requires check = ip | username | both");
  const rawThreshold = value.threshold;
  const threshold = rawThreshold === undefined ? -3
    : typeof rawThreshold === "number" && Number.isInteger(rawThreshold) && rawThreshold >= -100 && rawThreshold <= 100
      ? rawThreshold : (() => { throw new Error("threshold must be an integer between -100 and 100"); })();
  return { check, threshold };
}

export function reputationExpiryHours(env: Env): number {
  const raw = env.REPUTATION_EXPIRY_HOURS;
  if (raw === undefined) return 72;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 && parsed <= 8_760 ? parsed : 72;
}

function clampScore(score: number): number {
  return Math.max(-REPUTATION_SCORE_LIMIT, Math.min(REPUTATION_SCORE_LIMIT, score));
}

/** A login outcome moves the IP and username scores (fail −1 / success +1). */
export async function recordReputationOutcome(
  env: Env,
  ip: string | null,
  username: string | null,
  success: boolean,
): Promise<void> {
  const delta = success ? 1 : -1;
  const now = new Date().toISOString();
  const statements = [];
  if (ip && ip.length > 0 && ip.length <= 64) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO reputation_scores (kind, identifier, score, updated_at)
         VALUES ('ip', ?, ?, ?)
         ON CONFLICT (kind, identifier) DO UPDATE SET
           score = MAX(-${REPUTATION_SCORE_LIMIT}, MIN(${REPUTATION_SCORE_LIMIT}, score + ?)), updated_at = ?`,
      ).bind(ip, delta, now, delta, now),
    );
  }
  if (username && username.length > 0 && username.length <= 128) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO reputation_scores (kind, identifier, score, updated_at)
         VALUES ('username', ?, ?, ?)
         ON CONFLICT (kind, identifier) DO UPDATE SET
           score = MAX(-${REPUTATION_SCORE_LIMIT}, MIN(${REPUTATION_SCORE_LIMIT}, score + ?)), updated_at = ?`,
      ).bind(username, delta, now, delta, now),
    );
  }
  if (statements.length > 0) await env.DB.batch(statements);
}

/** The current score, or null when the entry is missing or expired. */
export async function reputationScore(env: Env, kind: "ip" | "username", identifier: string | null): Promise<number | null> {
  if (!identifier) return null;
  const cutoff = new Date(Date.now() - reputationExpiryHours(env) * 3_600_000).toISOString();
  const row = await env.DB.prepare(
    "SELECT score, updated_at AS updatedAt FROM reputation_scores WHERE kind = ? AND identifier = ? LIMIT 1",
  ).bind(kind, identifier).first<{ score: number; updatedAt: string }>();
  if (!row || row.updatedAt < cutoff) return null;
  return row.score;
}

/**
 * Policy evaluation: the policy fails when a relevant score is at or below
 * the threshold (accumulated failures reaching the limit deny the login).
 */
export async function evaluateReputation(
  env: Env,
  config: ReputationConfig,
  context: { clientIp: string | null; username: string | null },
): Promise<{ passing: boolean; messages: string[] }> {
  const relevant: Array<{ kind: "ip" | "username"; identifier: string | null }> = [];
  if (config.check === "ip" || config.check === "both") relevant.push({ kind: "ip", identifier: context.clientIp });
  if (config.check === "username" || config.check === "both") relevant.push({ kind: "username", identifier: context.username });
  for (const check of relevant) {
    const score = await reputationScore(env, check.kind, check.identifier);
    if (score !== null && score <= config.threshold) {
      return { passing: false, messages: [`${check.kind} reputation ${score} is at or below ${config.threshold}`] };
    }
  }
  return { passing: true, messages: [] };
}
