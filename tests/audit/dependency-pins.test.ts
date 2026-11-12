import { expect, test } from "bun:test";

test("workspace dependencies use exact versions", async () => {
  for (const path of ["package.json", "web/package.json"]) {
    const manifest = await Bun.file(path).json();
    for (const version of Object.values({ ...manifest.dependencies, ...manifest.devDependencies })) {
      expect(version).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
    }
  }
});
