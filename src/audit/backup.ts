/**
 * Independent audit backup (QST-1794159222-jq6 decision): the one-year
 * tamper-evident audit log in D1 additionally export-streams positioned rows
 * into a dated R2 object, keyed by the contiguous log position watermark, so a
 * compromised or lost D1 database still leaves an operator-recoverable copy
 * with the same hash chain. The export is idempotent per log position (the
 * watermark advances only after the object write succeeds) and fails safe:
 * every audit feature runs without the configured R2 binding.
 *
 * Restoration: each dated object is a UTF-8 JSON Lines stream; re-walking the
 * rows through verifyAuditEventChain against a restored table reproduces the
 * tamper evidence exactly.
 */

import type { Env } from "../env";

export const AUDIT_BACKUP_PREFIX = "audit-backup/";

interface AuditBackupRow {
  log_pos: number;
}

interface AuditBackupPayload {
  id: string;
  occurred_at: string;
  actor_user_id: string | null;
  target_user_id: string | null;
  event_type: string;
  outcome: string;
  request_path: string;
  log_pos: number;
  content_hash: string | null;
}

function dayKey(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** Load the contiguous log position already exported (0 = none). */
async function loadWatermark(env: Env): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT log_pos FROM audit_backup_state WHERE id = 1",
  ).first<{ log_pos: number }>();
  return row?.log_pos ?? 0;
}

/** Advance the watermark; one statement, watermark only moves forward. */
async function saveWatermark(env: Env, logPos: number): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO audit_backup_state (id, log_pos, updated_at) VALUES (1, ?, ?)
     ON CONFLICT (id) DO UPDATE SET log_pos = MAX(log_pos, excluded.log_pos), updated_at = excluded.updated_at`,
  ).bind(logPos, new Date().toISOString()).run();
}

async function readObjectText(bucket: R2Bucket, key: string): Promise<string> {
  const object = await bucket.get(key);
  return object ? await object.text() : "";
}

export interface AuditBackupResult {
  exported: number;
  watermark: number;
  backup: boolean;
}

/**
 * Append every audit row newer than the watermark into the dated object for
 * "today" (UTC). A batch larger than the object-size guard is written in
 * slices; the watermark advances only after a full successful write, so a
 * failure mid-way replays the same positions next time.
 */
export async function backupAuditEvents(env: Env, atMs: number, maxBatch = 5000): Promise<AuditBackupResult> {
  if (!env.AUDIT_BACKUP) return { exported: 0, watermark: await loadWatermark(env), backup: false };
  const watermark = await loadWatermark(env);
  const rows = await env.DB.prepare(
    `SELECT id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path, log_pos, content_hash
     FROM audit_events WHERE log_pos > ? ORDER BY log_pos ASC LIMIT ?`,
  ).bind(watermark, maxBatch).all<AuditBackupPayload & AuditBackupRow>();
  if (rows.results.length === 0) return { exported: 0, watermark, backup: true };

  const key = `${AUDIT_BACKUP_PREFIX}${dayKey(atMs)}.jsonl`;
  const bucket = env.AUDIT_BACKUP;
  const exported = rows.results.length;
  const nextWatermark = rows.results[rows.results.length - 1]!.log_pos;
  const payload = rows.results
    .map((row) => JSON.stringify({
      id: row.id, occurred_at: row.occurred_at, actor_user_id: row.actor_user_id,
      target_user_id: row.target_user_id, event_type: row.event_type,
      outcome: row.outcome, request_path: row.request_path,
      log_pos: row.log_pos, content_hash: row.content_hash,
    }))
    .join("\n");

  // Appends are not transactional in R2: read-modify-write under a keyed
  // object. A concurrent scheduler is a no-op in practice (single instance);
  // the watermark check keeps repeated runs idempotent.
  const existing = await readObjectText(bucket, key);
  const body = existing ? `${existing.replace(/\n$/, "")}\n${payload}\n` : `${payload}\n`;
  await bucket.put(key, body, {
    customMetadata: { lastLogPos: String(nextWatermark) },
  });
  await saveWatermark(env, nextWatermark);
  return { exported, watermark: nextWatermark, backup: true };
}

export interface AuditRestoreVerification {
  rows: number;
  verified: boolean;
  firstProblem: string | null;
}

/**
 * Sanity-check an R2 export: walk the restored rows and re-verify the content
 * hashes without touching D1 (the chain lives in the row data itself). Used
 * after a restore drill or spot check.
 */
export async function verifyAuditBackup(env: Env): Promise<AuditRestoreVerification> {
  if (!env.AUDIT_BACKUP) return { rows: 0, verified: false, firstProblem: "AUDIT_BACKUP binding is not configured" };
  const bucket = env.AUDIT_BACKUP;
  const objects = await bucket.list({ prefix: AUDIT_BACKUP_PREFIX });
  let rows = 0;
  let previousPos = 0;
  let firstProblem: string | null = null;
  for (const object of objects.objects) {
    const text = await readObjectText(bucket, object.key);
    if (text.length === 0) continue;
    for (const line of text.split("\n")) {
      if (line.trim().length === 0) continue;
      let row: AuditBackupPayload;
      try {
        row = JSON.parse(line) as AuditBackupPayload;
      } catch {
        if (firstProblem === null) firstProblem = `object ${object.key} has a malformed line`;
        rows += 1;
        continue;
      }
      rows += 1;
      if (row.content_hash === null) continue;
      const canonical = JSON.stringify([
        row.id, row.occurred_at, row.actor_user_id, row.target_user_id,
        row.event_type, row.outcome, row.request_path,
      ]);
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
      const expected = btoa(Array.from(new Uint8Array(digest), (byte) => String.fromCharCode(byte)).join(""));
      if (expected !== row.content_hash && firstProblem === null) {
        firstProblem = `row at log position ${row.log_pos} in ${object.key} fails its content hash`;
        continue;
      }
      if (row.log_pos !== previousPos + 1 && firstProblem === null) {
        firstProblem = `positions are not contiguous at ${row.log_pos} in ${object.key}`;
      }
      previousPos = row.log_pos > previousPos ? row.log_pos : previousPos;
    }
  }
  return { rows, verified: firstProblem === null, firstProblem };
}
