import { describe, expect, test } from "bun:test";

import { validateFingerprintConfig } from "../src/security/fingerprint";

function envWith(pairs: Record<string, string | undefined>): Record<string, string | undefined> {
  return {
    FINGERPRINT_MODE: "observe",
    FINGERPRINT_REGION: "us",
    FINGERPRINT_SERVER_API_KEY: "unit-test-key",
    ...pairs,
  };
}

describe("fingerprint configuration validation", () => {
  test("accepts HTTPS origins", () => {
    expect(() => validateFingerprintConfig(envWith({ FINGERPRINT_ALLOWED_ORIGINS: "https://auth.internal.example" }))).not.toThrow();
  });

  test("accepts http loopback dev origins", () => {
    const env = envWith({
      FINGERPRINT_ALLOWED_ORIGINS: "http://localhost:8787,http://127.0.0.1:8787",
    });
    expect(() => validateFingerprintConfig(env)).not.toThrow();
  });

  test("rejects plain http on public hosts", () => {
    expect(() => validateFingerprintConfig(envWith({ FINGERPRINT_ALLOWED_ORIGINS: "http://auth.internal.example" }))).toThrow();
  });

  test("rejects path-bearing or credential-bearing origins", () => {
    expect(() => validateFingerprintConfig(envWith({ FINGERPRINT_ALLOWED_ORIGINS: "https://auth.internal.example/login" }))).toThrow();
    expect(() => validateFingerprintConfig(envWith({ FINGERPRINT_ALLOWED_ORIGINS: "https://user:pw@auth.internal.example" }))).toThrow();
  });
});
