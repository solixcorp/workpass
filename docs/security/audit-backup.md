# Independent audit backup (R2)

**Decision (2026-11-10, resolving QST-1794159222-jq6):** the one-year tamper-evident audit
log in D1 additionally exports into a dedicated R2 bucket, because D1 itself is not claimed
immutable and a single store is a single failure surface. The restore path is the same hash
chain: exported rows re-verify with `verifyAuditEventChain` semantics byte-for-byte.

## Export contract

- Scheduled (daily cron, alongside the other cleanups) `src/audit/backup.ts` reads every
  positioned audit row **newer than the recorded watermark**
  (`audit_backup_state`, contiguous `log_pos`) and appends its canonical JSON to the dated
  UTF-8 JSON-Lines object `audit-backup/<YYYY-MM-DD>.jsonl` of the
  `AUDIT_BACKUP` R2 binding.
- Idempotent: the watermark advances only after the object write succeeds; a failed write
  loses nothing and the next run replays the same positions.
- Fails safe: without the `AUDIT_BACKUP` binding (binding removed, dev environment, or a
  bucket that does not exist) every audit feature runs exactly as before and the export
  reports `backup: false` — the D1 log remains authoritative.
- The exported lines keep `log_pos`, `content_hash` and all chained fields, so verification
  and audit-chain walking do not depend on D1.

## Verification

`verifyAuditBackup` walks every dated object, recomputes each entry's SHA-256 chain hash
against the same canonical form used for writes, and checks that log positions stay
contiguous. Any mismatch reports the object and log position of the first problem. Run it
as part of a restore drill, after recovering rows from R2, or periodically.

## Restore drill (runbook outline)

1. Create a scratch D1 database; recreate `audit_events` (same DDL as
   `src/db/schema.ts`).
2. Download all `audit-backup/*.jsonl` objects in date order and insert their rows into
   `audit_events` as-is.
3. Run `verifyAuditEventChain` against the restored table (or `verifyAuditBackup` over the
   objects directly): a clean bill of evidence means the restore is faithful.
4. Record the drill date and outcome in the operations log.

## Operators

- `wrangler r2 bucket create internal-auth-audit-backup` before deploying the binding;
  the binding ships in `wrangler.jsonc` and features fail safe until the bucket exists.
- Workers Logs retention is raised to its 30-day maximum (QST-1794159887-jwy decision);
  structured security audit retention remains one year in D1, and an audit-write failure
  still fails closed (the operation refuses to proceed without its audit record).
