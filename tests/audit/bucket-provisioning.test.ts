/**
 * Provisioning tests (docs/security/audit-backup.md, docs/operations/production-checklist.md):
 * the bucket name is read from the real wrangler.jsonc (single source of
 * truth), "already exists" is an idempotent no-op, and the predeploy flow
 * fails closed when the wrapper fails or the bucket never becomes visible.
 *
 * `bun test tests/audit/bucket-provisioning.test.ts`
 */

import { describe, expect, test } from "bun:test";
import { bucketNameFromConfig, creationOutcome, main } from "../../scripts/ensure-audit-backup-bucket";

describe("audit-backup bucket provisioning", () => {
  test("reads the bucket name from the real wrangler.jsonc", async () => {
    const name = await main("__nonexistent__", () => ({ code: 0, output: "" }));
    // A missing config errors out before touching wrangler.
    expect(name).toBe(2);
    const config = await Bun.file("wrangler.jsonc").text();
    expect(bucketNameFromConfig(config)).toBe("internal-auth-audit-backup");
  });

  test("treats an existing bucket as success without re-failing", () => {
    expect(creationOutcome("bucket internal-auth-audit-backup already exists")).toBe("exists");
    expect(creationOutcome("Created bucket internal-auth-audit-backup")).toBe("created");
    expect(creationOutcome("Error: something else went wrong")).toBe("failed");
  });

  test("predeploy flow: create, verify, and fail closed on an invisible bucket", async () => {
    const config = "./wrangler.jsonc";
    const calls: string[][] = [];
    const first = await main(config, (args) => {
      calls.push(args);
      return { code: 0, output: "Created bucket internal-auth-audit-backup." };
    });
    expect(first).toBe(0);
    expect(calls[0]).toEqual(["r2", "bucket", "create", "internal-auth-audit-backup"]);
    expect(calls[1]).toEqual(["r2", "bucket", "list"]);

    // A create wrapper failure that is not "already exists" fails the run.
    const failed = await main(config, (args) =>
      args[1] === "create"
        ? { code: 1, output: "Error: quota exceeded" }
        : { code: 0, output: "" });
    expect(failed).toBe(1);

    // A bucket that never becomes visible after creation fails closed too.
    const invisible = await main(config, () => ({ code: 0, output: "Created bucket." }));
    expect(invisible).toBe(1);
  });
});
