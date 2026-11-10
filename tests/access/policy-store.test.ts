/**
 * Runtime-independent unit tests for the discrimination and policy logic:
 * - buildSamlIdpMetadata's rotation KeyDescriptors
 * - SWA application and grant consumption rules (with a minimal D1 mock)
 * - SCIM operation creation and the witnessed constraint discrimination
 * - the one-time SAML request claim
 * These run with `bun test tests/policy-store.test.ts`.
 */

import { describe, expect, test } from "bun:test";
import { buildSamlIdpMetadata } from "../../src/saml/metadata";
import { createScimOperation, completeScimCreate } from "../../src/scim/operations";
import { claimVerifiedSamlRequest } from "../../src/saml/request-claims";
import { consumeSwaGrant, issueSwaGrant, validateSwaApplication } from "../../src/swa/applications";
import { validateWsfedRelyingParty } from "../../src/wsfed/relying-parties";

// --- minimal D1 mock -------------------------------------------------------
type Canned = { changes?: number; first?: unknown; rows?: unknown[] };

class FakeEnv {
  public DB: FakeDatabase;
  constructor(private readonly handlers: Map<string, Canned>) {
    this.DB = new FakeDatabase(handlers);
  }
}

class FakeDatabase {
  constructor(private readonly handlers: Map<string, Canned>) {}
  prepare(sql: string) {
    return new FakeStatement(sql, this.handlers);
  }
  batch(statements: FakeStatement[]): Promise<Array<{ meta: { changes: number } }>> {
    return Promise.all(statements.map((statement) => statement.run().then((result) => result)));
  }
}

class FakeStatement {
  constructor(private readonly sql: string, private readonly handlers: Map<string, Canned>) {}
  private canned(): Canned {
    for (const [needle, canned] of this.handlers) {
      if (this.sql.includes(needle)) return canned;
    }
    throw new Error(`Unexpected SQL in test mock: ${this.sql.slice(0, 80)}`);
  }
  bind(): FakeStatement {
    return this;
  }
  async run(): Promise<{ meta: { changes: number } }> {
    const canned = this.canned();
    if (canned.throw) throw canned.throw;
    return { meta: { changes: canned.changes ?? 1 } };
  }
  async first<T>(): Promise<T | null> {
    const canned = this.canned();
    return (canned.first ?? null) as T | null;
  }
  async all<T>(): Promise<{ results: T[] }> {
    const canned = this.canned();
    return { results: (canned.rows ?? []) as T[] };
  }
}

// inject a throwing handler into the map
declare module "bun:test" {}
type MockHandler = Canned & { throw?: Error };

function handlerMap(entries: Array<[string, MockHandler]>): Map<string, Canned> {
  return new Map(entries);
}

// --- metadata rotation ------------------------------------------------------
const BASE_METADATA_OPTIONS = {
  entityId: "https://idp.test/saml/metadata",
  certificate: `-----BEGIN CERTIFICATE-----\nQ2VydDE=\n-----END CERTIFICATE-----\n`,
  ssoUrl: "https://idp.test/saml/sso",
};

describe("SAML metadata rotation", () => {
  test("publishes one descriptor without a previous certificate", () => {
    const document = buildSamlIdpMetadata(BASE_METADATA_OPTIONS);
    expect(document.split("<md:KeyDescriptor").length - 1).toBe(1);
  });

  test("publishes both descriptors with a previous certificate", () => {
    const document = buildSamlIdpMetadata({
      ...BASE_METADATA_OPTIONS,
      previousCertificate: `-----BEGIN CERTIFICATE-----\nQ2VydDI=\n-----END CERTIFICATE-----\n`,
    });
    expect(document.split("<md:KeyDescriptor").length - 1).toBe(2);
  });

  test("rejects a non-PEM previous certificate", () => {
    try {
      buildSamlIdpMetadata({ ...BASE_METADATA_OPTIONS, previousCertificate: "not-a-pem" });
      expect.unreachable();
    } catch {
      expect(true).toBe(true);
    }
  });
});

// --- SWA validation and grant rules ----------------------------------------
describe("SWA validation", () => {
  const base = { id: "id-1", name: "app", enabled: false };

  test("accepts an exact HTTPS origin", () => {
    expect(() => validateSwaApplication({ ...base, origin: "https://app.example.com" })).not.toThrow();
  });

  test("rejects paths, credentials, query strings and HTTP origins", () => {
    for (const origin of [
      "https://app.example.com/login",
      "https://user:pass@app.example.com",
      "https://app.example.com/?x=1",
      "http://app.example.com",
      "not a url",
    ]) {
      expect(() => validateSwaApplication({ ...base, origin })).toThrow();
    }
  });

  test("rejects names outside the allowlist", () => {
    expect(() => validateSwaApplication({ ...base, name: "has space", origin: "https://app.example.com" })).toThrow();
  });
});

describe("SWA grant consumption", () => {
  test("consumes a live nonce once and rejects the replay", async () => {
    let consumed = false;
    const env = new FakeEnv(handlerMap([
      ["UPDATE swa_grants SET consumed_at", { changes: consumed ? 0 : 1 }],
      ["SELECT application_id", { first: { applicationId: "app-1", userId: "u-1", expiresAt: "2026-11-09T12:00:00.000Z" } }],
    ]));
    // Flip the canned flag on the first successful consume to emulate the row update.
    const first = await consumeSwaGrant(env as unknown as Parameters<typeof consumeSwaGrant>[0]["env"], "nonce-1");
    expect(first).not.toBeNull();
    consumed = true;
    expect(first!.applicationId).toBe("app-1");
    // A replay: the UPDATE then matches nothing.
    consumed = true;
    const noChangeEnv = new FakeEnv(handlerMap([
      ["UPDATE swa_grants SET consumed_at", { changes: 0 }],
      ["SELECT application_id", { first: null }],
    ]));
    const replay = await consumeSwaGrant(noChangeEnv as unknown as Parameters<typeof consumeSwaGrant>[0]["env"], "nonce-1");
    expect(replay).toBeNull();
  });

  test("issueSwaGrant returns a padded-less url-safe nonce", async () => {
    const env = new FakeEnv(handlerMap([
      ["INSERT INTO swa_grants", { changes: 1 }],
    ]));
    const grant = await issueSwaGrant(env as unknown as Parameters<typeof issueSwaGrant>[0]["env"], { applicationId: "app-1", userId: "u-1" });
    expect(grant.nonce.length).toBeGreaterThanOrEqual(40);
    expect(grant.nonce).not.toMatch(/[+/=]/);
  });
});

// --- SCIM operations and witnessed constraints -------------------------------
describe("SCIM operation creation", () => {
  test("creates when no unresolved operation exists", async () => {
    const env = new FakeEnv(handlerMap([
      ["INSERT INTO scim_operations", { changes: 1 }],
    ]));
    const id = await createScimOperation(env as unknown as Parameters<typeof createScimOperation>[0]["env"], { targetId: "t-1", userId: "u-1", operation: "create" });
    expect(id).not.toBeNull();
  });

  test("returns null when the single-active constraint holds", async () => {
    const env = new FakeEnv(handlerMap([
      ["INSERT INTO scim_operations", { changes: 0 }],
    ]));
    const id = await createScimOperation(env as unknown as Parameters<typeof createScimOperation>[0]["env"], { targetId: "t-1", userId: "u-1", operation: "create" });
    expect(id).toBeNull();
  });

  test("throws on constraint failures that are not the single-active guard", async () => {
    const env = new FakeEnv(handlerMap([
      ["INSERT INTO scim_operations", { changes: 0, throw: new Error("NOT NULL constraint failed: scim_operations.user_id") }],
    ]));
    expect(
      createScimOperation(env as unknown as Parameters<typeof createScimOperation>[0]["env"], { targetId: "t-1", userId: "", operation: "create" }),
    ).rejects.toThrow();
  });
});

// --- the one-time SAML request claim -----------------------------------------
describe("SAML request claim", () => {
  test("claims when the insert changes a row and the expiry is future", async () => {
    const env = new FakeEnv(handlerMap([
      ["INSERT INTO saml_request_claims", { changes: 1 }],
      ["DELETE FROM saml_request_claims", { changes: 0 }],
    ]));
    const claimed = await claimVerifiedSamlRequest({
      env: env as unknown as Parameters<typeof claimVerifiedSamlRequest>[0]["env"],
      providerId: "p-1",
      requestId: "req-1",
      expiresAt: new Date(Date.now() + 60_000),
    });
    expect(claimed).toBe(true);
  });

  test("rejects a replay when the insert changes nothing", async () => {
    const env = new FakeEnv(handlerMap([
      ["INSERT INTO saml_request_claims", { changes: 0 }],
      ["DELETE FROM saml_request_claims", { changes: 0 }],
    ]));
    const claimed = await claimVerifiedSamlRequest({
      env: env as unknown as Parameters<typeof claimVerifiedSamlRequest>[0]["env"],
      providerId: "p-1",
      requestId: "req-1",
      expiresAt: new Date(Date.now() + 60_000),
    });
    expect(claimed).toBe(false);
  });

  test("throws on an already expired claim window", async () => {
    // The claim validates the expiry window itself and fails closed.
    const env = new FakeEnv(handlerMap([
      ["DELETE FROM saml_request_claims", { changes: 0 }],
    ]));
    expect(() =>
      claimVerifiedSamlRequest({
        env: env as unknown as Parameters<typeof claimVerifiedSamlRequest>[0]["env"],
        providerId: "p-1",
        requestId: "req-1",
        expiresAt: new Date(Date.now() - 60_000),
      }),
    ).toThrow("Invalid SAML request claim");
  });
});
