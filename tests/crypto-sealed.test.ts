/**
 * Sealed-storage unit tests: the XChaCha20-Poly1305 envelope round-trips,
 * rejects tampering/wrong AAD/wrong cipher configuration, and the legacy
 * plaintext detector discriminates envelopes from raw base32 secrets.
 * These run with `bun test tests/crypto-sealed.test.ts`.
 */

import { describe, expect, test } from "bun:test";

import { looksSealed, sealBytes, sealString, unsealBytes, unsealString } from "../src/crypto/sealed";
import type { Env } from "../src/env";

const keyEnv = (): Env =>
  ({ AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(0x42))) }) as unknown as Env;

describe("sealed storage (XChaCha20-Poly1305, @noble/ciphers)", () => {
  test("seals and opens strings and bytes round-trip", async () => {
    const env = keyEnv();
    const envelope = await sealString(env, "JBSWY3DPEHPK3PXP");
    expect(looksSealed(envelope)).toBe(true);
    expect(envelope.startsWith("v1.")).toBe(true);
    expect(await unsealString(env, envelope)).toBe("JBSWY3DPEHPK3PXP");

    const bytes = crypto.getRandomValues(new Uint8Array(64));
    const opened = await unsealBytes(env, await sealBytes(env, bytes));
    expect(opened).toEqual(bytes);
  });

  test("every envelope uses a fresh CSPRNG nonce (two seals of one plaintext differ)", async () => {
    const env = keyEnv();
    const first = await sealString(env, "same input");
    const second = await sealString(env, "same input");
    expect(first).not.toBe(second);
    expect(await unsealString(env, second)).toBe("same input");
    expect(await unsealString(env, first)).toBe("same input");
  });

  test("tampered ciphertext, wrong AAD, and truncated envelopes all reject", async () => {
    const env = keyEnv();
    const aad = "mfa_hotp_token:user-1";
    const envelope = await sealString(env, "JBSWY3DPEHPK3PXP", aad);
    const parts = envelope.split(".");
    const raw = parts[2]!;
    const flipped = (raw[0] === "A" ? "B" : "A") + raw.slice(1);
    await expect(unsealString(env, [parts[0], parts[1], flipped].join("."), aad)).rejects.toThrow();
    await expect(unsealString(env, envelope, "mfa_hotp_token:user-2")).rejects.toThrow();
    await expect(unsealString(env, "legacy-plaintext-value", aad)).rejects.toThrow();
  });

  test("configuration is fail-closed: bad key/cipher never stores plaintext", async () => {
    const missing = { AEAD_SEALING_KEY: undefined, SEALED_STORAGE_CIPHER: "xchacha20poly1305" } as unknown as Env;
    await expect(sealString(missing, "secret")).rejects.toThrow("AEAD_SEALING_KEY must be configured");

    const shortKey = { AEAD_SEALING_KEY: btoa("0123"), SEALED_STORAGE_CIPHER: "xchacha20poly1305" } as unknown as Env;
    await expect(sealString(shortKey, "secret")).rejects.toThrow("32 bytes");

    const badCipher = { AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))), SEALED_STORAGE_CIPHER: "aes-128-cfb" } as unknown as Env;
    await expect(sealString(badCipher, "secret")).rejects.toThrow("not supported");
  });

  test("legacy plaintext rows are discriminated for lazy migration", () => {
    expect(looksSealed("JBSWY3DPEHPK3PXP")).toBe(false);
    expect(looksSealed("")).toBe(false);
    // A v1 envelope always starts with the version tag and has three parts.
    const shape = "v1.<nonce>.<payload>".replace(/<nonce>/g, "N".repeat(32)).replace(/<payload>/g, "P".repeat(44));
    expect(looksSealed(shape)).toBe(true);
    // A v2 (AES-GCM) envelope: 12-byte base64url nonce.
    const shapeV2 = "v2.<nonce>.<payload>".replace(/<nonce>/g, "N".repeat(16)).replace(/<payload>/g, "P".repeat(44));
    expect(looksSealed(shapeV2)).toBe(true);
    expect(looksSealed("v3.a.b")).toBe(false);
  });
});

describe("sealed storage (AES-256-GCM, WebCrypto, FIPS-aligned path)", () => {
  const aesEnv = (): Env =>
    ({ AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(0x42))), SEALED_STORAGE_CIPHER: "aes256gcm" }) as unknown as Env;

  test("seals as a v2 envelope and round-trips with tamper/AAD rejection", async () => {
    const env = aesEnv();
    const envelope = await sealString(env, "JBSWY3DPEHPK3PXP");
    expect(envelope.startsWith("v2.")).toBe(true);
    expect(await unsealString(env, envelope)).toBe("JBSWY3DPEHPK3PXP");

    const aad = "mfa_hotp_token:user-1";
    const parts = (await sealString(env, "secret", aad)).split(".");
    const raw = parts[2]!;
    const flipped = (raw[0] === "A" ? "B" : "A") + raw.slice(1);
    await expect(unsealString(env, [parts[0], parts[1], flipped].join("."), aad)).rejects.toThrow();
    await expect(unsealString(env, parts.join("."), "mfa_hotp_token:user-2")).rejects.toThrow();
  });

  test("reads are version-driven: ciphers stay readable across a switch", async () => {
    // v1 written under XChaCha reads while configured for AES-GCM.
    const chaChaEnv = keyEnv();
    const v1 = await sealString(chaChaEnv, "legacy row", "opaque_server_ake");
    expect((await unsealString(aesEnv(), v1, "opaque_server_ake"))).toBe("legacy row");
    // v2 written under AES-GCM reads while configured back to XChaCha.
    const v2 = await sealString(aesEnv(), "new row", "opaque_server_ake");
    expect(v2.startsWith("v2.")).toBe(true);
    expect(await unsealString(keyEnv(), v2, "opaque_server_ake")).toBe("new row");
  });

  test("unsupported ciphers still fail closed under either configuration", async () => {
    const bad = { AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))), SEALED_STORAGE_CIPHER: "aes-128-cfb" } as unknown as Env;
    await expect(sealString(bad, "secret")).rejects.toThrow("not supported");
    const bad2 = { AEAD_SEALING_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))), SEALED_STORAGE_CIPHER: "chacha20poly1305" } as unknown as Env;
    await expect(sealString(bad2, "secret")).rejects.toThrow("not supported");
  });
});
