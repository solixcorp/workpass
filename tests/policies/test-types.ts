import type { createTestD1 } from "../test-d1";
export type TestD1Db = ReturnType<typeof createTestD1>["db"];
