import { expect, test } from "bun:test";
import { backchannelFailureEvent } from "../src/oidc/logout-logging";

test("back-channel errors produce structured per-client events without request secrets", () => {
  expect(backchannelFailureEvent("back-channel logout to client client-1 returned 503"))
    .toEqual({ event: "oidc.backchannel_logout.failure", client_id: "client-1", reason: "http_503" });
  expect(backchannelFailureEvent("back-channel logout to client client-2 failed")?.reason).toBe("delivery_failed");
  expect(backchannelFailureEvent("back-channel logout: unable to resolve subject for client client-3")?.reason).toBe("subject_resolution_failed");
  expect(backchannelFailureEvent("back-channel logout planning failed")?.client_id).toBeNull();
  expect(backchannelFailureEvent("unrelated log message")).toBeNull();
});
