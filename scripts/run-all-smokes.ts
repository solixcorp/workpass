/**
 * Operator tooling: run every verification smoke in order against a running
 * worker. Each smoke is self-contained (its own cookies, credentials, and
 * optional bootstrap stages) and exits non-zero on the first failure, so this
 * runner also serves as the post-deployment verification wave.
 *
 *   bun run smoke --migrate-token <t> --admin-token <t>
 */

const sharedArgs = Bun.argv.slice(2);
const smokes = [
  "scripts/oidc-smoke.ts",
  "scripts/passkey-smoke.ts",
  "scripts/session-revocation-smoke.ts",
  "scripts/swa-smoke.ts",
  "scripts/wsfed-smoke.ts",
  "scripts/scim-inbound-smoke.ts",
  "scripts/opaque-smoke.ts",
];

for (const smoke of smokes) {
  console.log(`=== ${smoke}`);
  const child = Bun.spawnSync(["bun", "run", smoke, ...sharedArgs], {
    stdout: "inherit",
    stderr: "inherit",
  });
  if (child.exitCode !== 0) {
    console.error(`${smoke} failed with exit code ${child.exitCode}`);
    process.exit(child.exitCode ?? 1);
  }
}
console.log("all smokes passed");
