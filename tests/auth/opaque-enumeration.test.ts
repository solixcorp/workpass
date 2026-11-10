import { describe, expect, test } from "bun:test";
import {
  getOpaqueConfig,
  KE2,
  OpaqueClient,
  OpaqueID,
  ScryptMemHardFn,
} from "@cloudflare/opaque-ts";
import { opaqueRoutes } from "../../src/auth/opaque-routes";
import { opaqueServer } from "../../src/auth/opaque";
import { ensureApplicationTables } from "../../src/db/schema";
import { sealString } from "../../src/crypto/sealed";
import type { Env } from "../../src/env";
import { createTestD1 } from "../test-d1";

const ORIGIN = "https://idp.test";
const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);

const toWire = (bytes: number[]): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
const fromWire = (wire: string): number[] => {
  const binary = atob(wire.replace(/-/g, "+").replace(/_/g, "/"));
  return Array.from(binary, (char) => char.charCodeAt(0));
};

async function seededEnv(): Promise<Env> {
  const testD1 = createTestD1();
  const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(9)));
  const env = {
    DB: testD1.db,
    AUTH_BASE_URL: ORIGIN,
    AUTH_SECRET: "opaque-enumeration-secret-0123456789",
    OPAQUE_MASTER_KEY: key,
    AEAD_SEALING_KEY: key,
  } as unknown as Env;
  await ensureApplicationTables(env);
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS "user" (id TEXT PRIMARY KEY, email TEXT, username TEXT, banned INTEGER)`,
  ).run();
  await env.DB.prepare(
    `INSERT INTO "user" (id, email, username, banned) VALUES
       ('u-enrolled', 'enrolled@corp.test', 'enrolled', 0),
       ('u-plain', 'plain@corp.test', 'plain', 0)`,
  ).run();

  // Enroll u-enrolled with a real OPAQUE record, exactly as register/* stores it.
  const { server } = await opaqueServer(env);
  const client = new OpaqueClient(config, ScryptMemHardFn);
  const request = await client.registerInit("correct horse battery");
  if (request instanceof Error) throw request;
  const response = await server.registerInit(request, "enrolled@corp.test");
  if (response instanceof Error) throw response;
  const finished = await client.registerFinish(response, ORIGIN, "enrolled@corp.test");
  if (finished instanceof Error) throw finished;
  const sealed = await sealString(env, JSON.stringify(finished.record.serialize()), "opaque_record:u-enrolled");
  await env.DB.prepare(
    `INSERT INTO opaque_credential_records (user_id, record, credential_identifier, created_at, updated_at)
     VALUES ('u-enrolled', ?, 'enrolled@corp.test', '2026-01-01', '2026-01-01')`,
  ).bind(sealed).run();
  return env;
}

async function start(env: Env, username: string, password: string) {
  const client = new OpaqueClient(config, ScryptMemHardFn);
  const ke1 = await client.authInit(password);
  if (ke1 instanceof Error) throw ke1;
  const response = await opaqueRoutes.request(
    "/api/opaque/auth/start",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": "203.0.113.7" },
      body: JSON.stringify({ username, ke1: toWire(ke1.serialize()) }),
    },
    env,
  );
  return { client, response, body: (await response.json()) as Record<string, string> };
}

describe("OPAQUE login enumeration resistance", () => {
  test("auth/start answers identically for enrolled, unenrolled and unknown identifiers", async () => {
    const env = await seededEnv();
    const results = await Promise.all([
      start(env, "Enrolled@Corp.test", "correct horse battery"),
      start(env, "plain@corp.test", "anything"),
      start(env, "nobody@corp.test", "anything"),
    ]);
    for (const [index, result] of results.entries()) {
      expect(result.response.status).toBe(200);
      expect(Object.keys(result.body).sort()).toEqual(["credentialIdentifier", "ke2", "serverIdentity", "transcriptId"]);
      // The response only echoes the normalized identifier the caller sent.
      expect(result.body.credentialIdentifier).toBe(
        ["enrolled@corp.test", "plain@corp.test", "nobody@corp.test"][index],
      );
      expect(result.body.serverIdentity).toBe(ORIGIN);
      expect(result.body.ke2.length).toBe(results[0]!.body.ke2.length);
    }
  });

  test("only the correct password for an enrolled email completes the client proof", async () => {
    const env = await seededEnv();
    const finishFor = async (username: string, password: string) => {
      const { client, body } = await start(env, username, password);
      return await client.authFinish(
        KE2.deserialize(config, fromWire(body.ke2)),
        body.serverIdentity,
        body.credentialIdentifier,
      );
    };
    expect(await finishFor("enrolled@corp.test", "correct horse battery")).not.toBeInstanceOf(Error);
    expect(await finishFor("enrolled@corp.test", "wrong password")).toBeInstanceOf(Error);
    expect(await finishFor("plain@corp.test", "anything")).toBeInstanceOf(Error);
    expect(await finishFor("nobody@corp.test", "anything")).toBeInstanceOf(Error);
  });

  test("auth/finish rejects garbage proofs for unknown accounts with the same 401", async () => {
    const env = await seededEnv();
    const unknown = await start(env, "nobody@corp.test", "anything");
    const finish = await opaqueRoutes.request(
      "/api/opaque/auth/finish",
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": "203.0.113.7" },
        body: JSON.stringify({ username: "nobody@corp.test", ke3: "AAAA", transcriptId: unknown.body.transcriptId }),
      },
      env,
    );
    expect(finish.status).toBe(401);
  });
});
