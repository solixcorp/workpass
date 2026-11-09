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
  "scripts/mfa-proof-smoke.ts",
  "scripts/passkey-smoke.ts",
  "scripts/session-revocation-smoke.ts",
  "scripts/swa-smoke.ts",
  "scripts/wsfed-smoke.ts",
  "scripts/scim-inbound-smoke.ts",
  // OPAQUE login is gated by account state and the shared device-risk
  // pipeline (src/auth/opaque-login.ts), re-enabled for the smoke wave.
  "scripts/opaque-smoke.ts",
  // Token exchange (RFC 8693) only validates on a worker started with
  // ENABLE_TOKEN_EXCHANGE=true and a seeded allowlist (see token-exchange-smoke.ts).
  "scripts/token-exchange-smoke.ts",
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
