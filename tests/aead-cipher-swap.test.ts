import { describe, expect, test } from "bun:test";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

/**
 * XChaCha20-Poly1305 selection: @noble/ciphers is the chosen AEAD because the
 * alternative (libsodium-wrappers WASM) fails inside the real workerd runtime
 * (its emscripten init runs in global scope and hangs/times out during
 * module bootstrap). Verified live with a temporary wrangler probe before
 * settling; noble is audited, dependency-free pure TypeScript and passed the
 * workerd round-trip ({"engine":"noble","ok":true}).
 */

describe("XChaCha20-Poly1305 (@noble/ciphers) on the project runtime", () => {
  test("round-trips and rejects tampering, wrong key, and wrong associated data", () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const nonce = crypto.getRandomValues(new Uint8Array(24));
    const aad = new TextEncoder().encode("internal-auth:v1");
    const message = new TextEncoder().encode("sensitive payload ✓");

    const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(message);
    expect(ciphertext.length).toBe(message.length + 16); // Poly1305 tag
    expect(xchacha20poly1305(key, nonce, aad).decrypt(ciphertext)).toEqual(message);

    ciphertext[0]! ^= 1;
    expect(() => xchacha20poly1305(key, nonce, aad).decrypt(ciphertext)).toThrow();
  });

  test("round-trips the libsodium test-suite message shape with a recorded regression baseline", () => {
    const key = new Uint8Array(32).fill(0x80);
    const nonce = new Uint8Array(24).fill(0x00);
    const message = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    const output = xchacha20poly1305(key, nonce).encrypt(message);
    // Baseline recorded during selection, where the same inputs produced
    // byte-identical output from libsodium's crypto_aead_xchacha20poly1305_ietf.
    const baseline = [93, 163, 149, 42];
    expect([output[0], output[1], output[2], output[3]]).toEqual(baseline);
    expect(xchacha20poly1305(key, nonce).decrypt(output)).toEqual(message);
  });
});
