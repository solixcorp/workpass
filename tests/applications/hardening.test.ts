import { expect, test } from "bun:test";
import { ICON_MAX_BYTES, readIconBytes, sniffImageType } from "../../src/applications/icons";
import { validateClientInput } from "../../src/applications/oidc-clients";

test("WebP requires RIFF and WEBP at their respective offsets", () => {
  const webp = new TextEncoder().encode("RIFF1234WEBP");
  expect(sniffImageType(webp)).toEqual({ contentType: "image/webp", ext: "webp" });
  expect(sniffImageType(new TextEncoder().encode("RIFFWEBP1234"))).toBeNull();
  expect(sniffImageType(new TextEncoder().encode("NOPE1234WEBP"))).toBeNull();
  expect(sniffImageType(webp.slice(0, 11))).toBeNull();
});

test("oversized icons are rejected before arrayBuffer", async () => {
  let read = false;
  const file = { size: ICON_MAX_BYTES + 1, arrayBuffer: async () => { read = true; throw new Error("read"); } } as Blob;
  expect(await readIconBytes(file)).toBeNull();
  expect(read).toBe(false);
  expect((await readIconBytes(new Blob([new Uint8Array(ICON_MAX_BYTES)])))?.length).toBe(ICON_MAX_BYTES);
});

test("grant validation rejects inherited properties", () => {
  for (const grant of ["toString", "constructor", "__proto__"]) {
    expect(() => validateClientInput({ grants: ["authorization_code", grant] }, "patch")).toThrow();
  }
  expect(validateClientInput({ grants: ["authorization_code", "refresh_token"] }, "patch").grants)
    .toEqual(["authorization_code", "refresh_token"]);
});
