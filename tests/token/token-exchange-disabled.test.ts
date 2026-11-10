import { expect, test } from "bun:test";
import worker from "../../src/index";
import type { Env } from "../../src/env";

test("unfinished token exchange is not exposed", async () => {
  const request = new Request("http://localhost/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
  });
  const response = await worker.fetch(request, {} as Env, {} as ExecutionContext);
  expect(response.status).toBe(404);
});
