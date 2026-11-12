/**
 * Independent audit-backup tests (docs/security/audit-backup.md): the
 * watermark-guarded R2 export, idempotent replay after a simulated object
 * failure, day-keyed continuation across scheduled runs, and the restored
 * chain verification over the exported rows.
 *
 * `bun test tests/audit-backup.test.ts`
 */

import { describe, expect, test } from "bun:test";
import { TestD1 } from "../helpers/test-d1";
import { ensureApplicationTables } from "../../src/db/schema";
import { insertAuditEvent, updateAuditEvent } from "../../src/audit/store";
import { AUDIT_BACKUP_PREFIX, backupAuditEvents, verifyAuditBackup } from "../../src/audit/backup";

class FakeR2Bucket {
  readonly store = new Map<string, string>();

  async get(key: string): Promise<{ text: () => Promise<string> } | null> {
    const value = this.store.get(key);
    return value === undefined ? null : { text: async () => value };
  }

  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async list(options: { prefix: string }): Promise<{ objects: Array<{ key: string }> }> {
    return { objects: [...this.store.keys()].filter((key) => key.startsWith(options.prefix)).map((key) => ({ key })) };
  }
}

function stub(): { env: never; db: TestD1; bucket: FakeR2Bucket } {
  const db = new TestD1();
  const bucket = new FakeR2Bucket();
  const env = { DB: db, AUDIT_BACKUP: bucket } as never;
  return { env, db, bucket };
}

async function seedAuditRows(db: TestD1, count: number): Promise<void> {
  for (let i = 0; i < count; i += 1) {
    await insertAuditEvent({ DB: db } as never, {
      id: crypto.randomUUID(),
      actor_user_id: "actor",
      target_user_id: null,
      event_type: "test.event",
      outcome: "success",
      request_path: "/test",
    });
  }
}

describe("audit backup export", () => {
  test("stops at an unfinished event and exports its final fields after finalization", async () => {
    const { env, db, bucket } = stub();
    await ensureApplicationTables(env);
    await seedAuditRows(db, 1);
    await insertAuditEvent(env, { id: "pending", actor_user_id: null, target_user_id: null, event_type: "test.pending", outcome: "started", request_path: "/test" });
    await seedAuditRows(db, 2);
    const at = Date.parse("2026-11-10T09:00:00Z");
    expect(await backupAuditEvents(env, at)).toEqual({ exported: 1, watermark: 1, backup: true });
    expect(await backupAuditEvents(env, at)).toEqual({ exported: 0, watermark: 1, backup: true });
    await updateAuditEvent(env, "pending", { actor_user_id: "actor-final", target_user_id: "target-final", outcome: "failure" });
    expect(await backupAuditEvents(env, at)).toEqual({ exported: 3, watermark: 4, backup: true });
    const lines = bucket.store.get(`${AUDIT_BACKUP_PREFIX}2026-11-10.jsonl`)!.trim().split("\n").map((line) => JSON.parse(line));
    expect(lines[2]).toMatchObject({ id: "pending", outcome: "failure", actor_user_id: "actor-final", target_user_id: "target-final" });
    expect(await verifyAuditBackup(env)).toEqual({ rows: 4, verified: true, firstProblem: null, manifest: "present", lastLogPos: 4 });
  });
  test("exports new rows into a dated object keyed by log position", async () => {
    const { env, db, bucket } = stub();
    await ensureApplicationTables(env);
    await seedAuditRows(db, 3);
    const first = await backupAuditEvents(env, Date.parse("2026-11-10T09:00:00Z"));
    expect(first.backup).toBe(true);
    expect(first.exported).toBe(3);
    expect(first.watermark).toBe(3);
    const key = `${AUDIT_BACKUP_PREFIX}2026-11-10.jsonl`;
    const text = bucket.store.get(key)!;
    expect(text.split("\n").filter((l) => l.trim().length > 0)).toHaveLength(4);

    // Watermark stops repeats.
    const repeat = await backupAuditEvents(env, Date.parse("2026-11-10T10:00:00Z"));
    expect(repeat.exported).toBe(0);
    expect(repeat.watermark).toBe(3);

    // New rows continue from the watermark across objects.
    await seedAuditRows(db, 2);
    const later = await backupAuditEvents(env, Date.parse("2026-11-11T09:00:00Z"));
    expect(later.exported).toBe(2);
    expect(later.watermark).toBe(5);
    expect(bucket.store.has(`${AUDIT_BACKUP_PREFIX}2026-11-11.jsonl`)).toBe(true);
  });

  test("a failed object write advances nothing and survives to replay", async () => {
    const { env, db, bucket } = stub();
    await ensureApplicationTables(env);
    await seedAuditRows(db, 2);
    const failing = {
      get: (key: string) => bucket.get(key),
      list: (options: { prefix: string }) => bucket.list(options),
      put: async () => { throw new Error("r2 unavailable"); },
    };
    const envBroken = { DB: db, AUDIT_BACKUP: failing } as never;
    await expect(backupAuditEvents(envBroken, Date.parse("2026-11-10T09:00:00Z"))).rejects.toThrow("r2 unavailable");
    // The watermark did not move.
    const row = await db.prepare("SELECT log_pos FROM audit_backup_state WHERE id = 1").first<{ log_pos: number }>();
    expect(row?.log_pos ?? 0).toBe(0);
    // A later healthy run replays the same positions.
    const retried = await backupAuditEvents(env, Date.parse("2026-11-10T09:05:00Z"));
    expect(retried.exported).toBe(2);
    expect(retried.watermark).toBe(2);
  });

  test("verifyAuditBackup validates the exported chain and detects tampering", async () => {
    const { env, db, bucket } = stub();
    await ensureApplicationTables(env);
    await seedAuditRows(db, 4);
    await backupAuditEvents(env, Date.parse("2026-11-10T09:00:00Z"));
    const clean = await verifyAuditBackup(env);
    expect(clean.verified).toBe(true);
    expect(clean.rows).toBe(4);
    // Tamper with one exported outcome value.
    const key = `${AUDIT_BACKUP_PREFIX}2026-11-10.jsonl`;
    const text = bucket.store.get(key)!;
    bucket.store.set(key, text.replace('"test.event"', '"test.event.tampered"'));
    const tampered = await verifyAuditBackup(env);
    expect(tampered.verified).toBe(false);
    expect(tampered.firstProblem).toContain("content hash");
  });

  test("rejects empty and missing hashes; legacy archives report absent manifests", async () => {
    const { env, db, bucket } = stub();
    await ensureApplicationTables(env);
    expect((await verifyAuditBackup(env)).verified).toBe(false);
    await seedAuditRows(db, 2);
    await backupAuditEvents(env, Date.parse("2026-11-10T09:00:00Z"));
    const key = `${AUDIT_BACKUP_PREFIX}2026-11-10.jsonl`;
    const lines = bucket.store.get(key)!.trim().split("\n");
    bucket.store.set(key, lines.slice(0, -1).join("\n") + "\n");
    expect(await verifyAuditBackup(env)).toMatchObject({ verified: true, manifest: "absent", lastLogPos: 2 });
    const row = JSON.parse(lines[0]!);
    row.content_hash = null;
    bucket.store.set(key, [JSON.stringify(row), ...lines.slice(1)].join("\n") + "\n");
    expect(await verifyAuditBackup(env)).toMatchObject({ verified: false, manifest: "present", firstProblem: expect.stringContaining("missing its content hash") });
    const badManifest = JSON.parse(lines[2]!);
    badManifest.rowCount = 3;
    bucket.store.set(key, [lines[0], lines[1], JSON.stringify(badManifest)].join("\n"));
    expect((await verifyAuditBackup(env)).firstProblem).toContain("invalid manifest");
  });

  test("every audit feature fails safe without the R2 binding", async () => {
    const { env, db } = stub();
    await ensureApplicationTables(env);
    await seedAuditRows(db, 1);
    const result = await backupAuditEvents({ DB: db } as never, Date.parse("2026-11-10T09:00:00Z"));
    expect(result.backup).toBe(false);
    const verification = await verifyAuditBackup({ DB: db } as never);
    expect(verification.verified).toBe(false);
    expect(verification.firstProblem).toContain("AUDIT_BACKUP");
  });
});
