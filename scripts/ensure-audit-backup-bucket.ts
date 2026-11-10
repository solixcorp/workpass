/**
 * Operator provisioning: guarantee the R2 bucket named in wrangler.jsonc
 * (the AUDIT_BACKUP binding) exists before the worker referencing it deploys.
 *
 * Idempotent — safe to run before every deploy (wired as the `predeploy`
 * lifecycle hook, so `bun run deploy` provisions first) and as part of the
 * bootstrap deployment window. The bucket name is read from wrangler.jsonc so
 * the config and the script can never drift apart.
 *
 *   bun run scripts/ensure-audit-backup-bucket.ts
 */

import { spawnSync } from "node:child_process";

export const DEFAULT_CONFIG_PATH = "wrangler.jsonc";

/** Pull the r2 bucket name out of the wrangler config text (jsonc-tolerant). */
export function bucketNameFromConfig(configText: string): string | null {
  const r2Section = configText.match(/"r2_buckets"\s*:\s*\[/);
  if (!r2Section) return null;
  const after = configText.slice(r2Section.index, configText.indexOf("]", r2Section.index));
  const name = after.match(/"bucket_name"\s*:\s*"([^"]+)"/);
  return name?.[1] ?? null;
}

/**
 * Wrangler reports an existing bucket with its own line; anything carrying
 * that phrase is a successful no-op, never a failure.
 */
export function creationOutcome(output: string): "created" | "exists" | "failed" {
  if (/already exist/i.test(output)) return "exists";
  if (/created/i.test(output)) return "created";
  return "failed";
}

export function runWrangler(args: string[]): { code: number; output: string } {
  const child = spawnSync("bunx", ["wrangler", ...args], { encoding: "utf8" });
  return {
    code: child.status ?? 1,
    output: `${child.stdout ?? ""}${child.stderr ?? ""}`,
  };
}

export async function main(
  configPath = DEFAULT_CONFIG_PATH,
  runner: (args: string[]) => { code: number; output: string } = runWrangler,
): Promise<number> {
  let configText: string;
  try {
    configText = await Bun.file(configPath).text();
  } catch (error) {
    console.error(`ensure-audit-backup-bucket: config ${configPath} is unreadable (${error instanceof Error ? error.message : "unknown error"})`);
    return 2;
  }
  const bucket = bucketNameFromConfig(configText);
  if (!bucket) {
    console.error(`ensure-audit-backup-bucket: no r2 bucket_name found in ${configPath}`);
    return 2;
  }
  console.log(`=== ensuring R2 bucket ${bucket}`);
  const first = runner(["r2", "bucket", "create", bucket]);
  const outcome = creationOutcome(first.output);
  if (first.code !== 0 && outcome !== "exists") {
    console.error(`ensure-audit-backup-bucket: bucket create failed:\n${first.output}`);
    return first.code;
  }
  console.log(outcome === "exists" ? `bucket ${bucket} already exists` : `bucket ${bucket} created`);

  // Confirm the bucket resolves through the operator's account before deploy.
  const list = runner(["r2", "bucket", "list"]);
  if (list.code !== 0) {
    console.error(`ensure-audit-backup-bucket: bucket list failed:\n${list.output}`);
    return list.code;
  }
  const present = list.output.includes(bucket);
  console.log(present ? `verified: ${bucket} is visible` : `WARNING: ${bucket} not found in bucket list`);
  return present ? 0 : 1;
}

// Invoked directly: `bun run scripts/ensure-audit-backup-bucket.ts`.
if (import.meta.main) {
  process.exit(await main());
}
