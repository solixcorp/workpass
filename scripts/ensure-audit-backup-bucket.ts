/**
 * Operator provisioning: guarantee every R2 bucket named in wrangler.jsonc
 * (AUDIT_BACKUP and APPLICATION_ICONS) exists before the worker referencing it deploys.
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

/** Every r2 bucket name in the wrangler config text (jsonc-tolerant). */
export function bucketNamesFromConfig(configText: string): string[] {
  const r2Section = configText.match(/"r2_buckets"\s*:\s*\[/);
  if (!r2Section) return [];
  const after = configText.slice(r2Section.index, configText.indexOf("]", r2Section.index));
  return [...after.matchAll(/"bucket_name"\s*:\s*"([^"]+)"/g)].map((match) => match[1]!);
}

/** The first bucket (the audit backup), kept for callers that only need one. */
export function bucketNameFromConfig(configText: string): string | null {
  return bucketNamesFromConfig(configText)[0] ?? null;
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
  const buckets = bucketNamesFromConfig(configText);
  if (buckets.length === 0) {
    console.error(`ensure-audit-backup-bucket: no r2 bucket_name found in ${configPath}`);
    return 2;
  }
  for (const bucket of buckets) {
    console.log(`=== ensuring R2 bucket ${bucket}`);
    const first = runner(["r2", "bucket", "create", bucket]);
    const outcome = creationOutcome(first.output);
    if (first.code !== 0 && outcome !== "exists") {
      console.error(`ensure-audit-backup-bucket: bucket create failed:\n${first.output}`);
      return first.code;
    }
    console.log(outcome === "exists" ? `bucket ${bucket} already exists` : `bucket ${bucket} created`);
  }

  // Confirm every bucket resolves through the operator's account before deploy.
  const list = runner(["r2", "bucket", "list"]);
  if (list.code !== 0) {
    console.error(`ensure-audit-backup-bucket: bucket list failed:\n${list.output}`);
    return list.code;
  }
  let missing = 0;
  for (const bucket of buckets) {
    const present = list.output.includes(bucket);
    if (!present) missing += 1;
    console.log(present ? `verified: ${bucket} is visible` : `WARNING: ${bucket} not found in bucket list`);
  }
  return missing === 0 ? 0 : 1;
}

// Invoked directly: `bun run scripts/ensure-audit-backup-bucket.ts`.
if (import.meta.main) {
  process.exit(await main());
}
