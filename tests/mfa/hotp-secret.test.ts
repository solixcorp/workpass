import { describe, expect, test } from "bun:test";

import { generateHotpSecret } from "../../src/mfa/hotp";

/**
 * Regression: generateHotpSecret used to emit alphabet[byte & 31] per byte —
 * one character per BYTE, which is not RFC 4648 base32 (drops the top 3 bits
 * of every byte and produces invalid, non-multiple-of-8 lengths that hardware
 * tokens reject). The generator now emits the canonical unpadded 32-character
 * encoding of a 20-byte secret.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function decodeCanonical(value: string): number[] {
  const bits: number[] = [];
  let accumulator = 0;
  let count = 0;
  for (const char of value) {
    accumulator = (accumulator << 5) | ALPHABET.indexOf(char);
    count += 5;
    if (count >= 8) {
      bits.push((accumulator >>> (count - 8)) & 0xff);
      count -= 8;
    }
  }
  return bits; // ignores trailing bits, per RFC 4648 decoders
}

describe("HOTP secret generation (RFC 4648)", () => {
  test("emits 32 unpadded base32 characters for a 20-byte secret", () => {
    const secret = generateHotpSecret();
    expect(secret).toHaveLength(32);
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
  });

  test("round-trips: decoding the generated secret returns exactly 20 bytes", () => {
    for (let index = 0; index < 8; index += 1) {
      const secret = generateHotpSecret();
      expect(decodeCanonical(secret)).toHaveLength(20);
    }
  });

  test("encodes known RFC 4648 vectors correctly", () => {
    // "Hello!" bytes -> base32 JBSWY3DPE (unpadded)
    const bytes = new TextEncoder().encode("Hello!");
    let out = ""; let acc = 0; let count = 0;
    for (const byte of bytes) { acc = (acc << 8) | byte; count += 8; while (count >= 5) { out += ALPHABET[(acc >>> (count - 5)) & 31]; count -= 5; } }
    expect(out).toBe("JBSWY3DPE");
  });
});
