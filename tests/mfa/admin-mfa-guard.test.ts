import { expect, test } from "bun:test";
import { TestD1 } from "../helpers/test-d1";
import { ensureApplicationTables } from "../../src/db/schema";
import type { Env } from "../../src/env";
import { administratorMfaAllowed } from "../../src/security/authorization";
import { openStepUpChallenge } from "../../src/security/step-up";
import { recordSessionMfaProof } from "../../src/mfa/second-factor";

test("administrator MFA gate rejects pending sessions and permits only the proven session", async () => {
  const db = new TestD1();
  const env = { DB: db, AUTH_SECRET: "secret", AUTH_BASE_URL: "https://idp.test" } as unknown as Env;
  await ensureApplicationTables(env);
  const session = { user: { id: "admin", role: "admin" }, session: { token: "a" } };
  expect(await administratorMfaAllowed(env, session)).toBe(true);
  await openStepUpChallenge({ env, userId: "admin", sessionToken: "a", reasons: [], requestPath: "/" });
  expect(await administratorMfaAllowed(env, session)).toBe(false);
  await recordSessionMfaProof(env, "b", "admin", "hotp");
  expect(await administratorMfaAllowed(env, session)).toBe(false);
  await recordSessionMfaProof(env, "a", "admin", "hotp");
  expect(await administratorMfaAllowed(env, session)).toBe(true);
});
