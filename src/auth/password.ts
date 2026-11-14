// Workers cap PBKDF2 at 100,000 iterations (deriveBits throws above that), so
// this is the most the runtime allows. Passwords are only hashed here for
// bootstrap and recovery; sign-in uses OPAQUE.
const PBKDF2_ITERATIONS = 100_000;
const PASSWORD_HASH_PREFIX = `pbkdf2-sha256$${PBKDF2_ITERATIONS}$`;

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password.normalize("NFKC")),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    key,
    256,
  );

  return `${PASSWORD_HASH_PREFIX}${bytesToHex(salt)}$${bytesToHex(new Uint8Array(bits))}`;
}

export async function verifyPassword(input: {
  hash: string;
  password: string;
}): Promise<boolean> {
  if (!input.hash.startsWith("pbkdf2-sha256$")) {
    const { verifyPassword: verifyLegacyPassword } = await import("better-auth/crypto");
    return verifyLegacyPassword(input);
  }

  const [algorithm, iterationsValue, saltHex, expectedHex] = input.hash.split("$");
  if (
    algorithm !== "pbkdf2-sha256" ||
    iterationsValue !== String(PBKDF2_ITERATIONS) ||
    !saltHex ||
    !expectedHex
  ) {
    return false;
  }

  try {
    const salt = Uint8Array.from(hexToBytes(saltHex));
    const expected = hexToBytes(expectedHex);
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(input.password.normalize("NFKC")),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt,
          iterations: Number(iterationsValue),
        },
        key,
        expected.length * 8,
      ),
    );
    if (bits.length !== expected.length) return false;

    let difference = 0;
    for (let index = 0; index < bits.length; index += 1) {
      difference |= bits[index]! ^ expected[index]!;
    }
    return difference === 0;
  } catch {
    return false;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) {
    throw new Error("Invalid encoded hash");
  }

  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
