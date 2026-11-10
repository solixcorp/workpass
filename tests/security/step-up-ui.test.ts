import { describe, expect, test } from "bun:test";
import { stepUpUi } from "../../src/security/step-up-ui";

describe("step-up screen definition", () => {
  test("offers exactly the methods the account can complete, plus backup codes", () => {
    const ui = stepUpUi(["totp"]);
    expect(ui.methods.map((method) => method.key)).toEqual(["totp", "backup_code"]);
    expect(ui.title).toBe("추가 인증");
    expect(ui.submit.label).toBeTruthy();
    expect(ui.alternatives[0]?.action).toBe("cancel");
  });

  test("an emailed/SMS code must be requested before it can be entered", () => {
    const otp = stepUpUi(["otp"]).methods.find((method) => method.key === "otp");
    expect(otp?.send?.label).toBeTruthy();
    expect(otp?.input).toBe("otp6");
  });

  test("every enrolled method is offered, backup codes only with an authenticator app", () => {
    const ui = stepUpUi(["totp", "backup_code", "duo_push", "hotp", "mystery"]);
    expect(ui.methods.map((method) => method.key)).toEqual(["totp", "backup_code", "duo_push", "hotp"]);
    expect(stepUpUi(["otp"]).methods.map((method) => method.key)).toEqual(["otp"]);
    expect(stepUpUi(["duo_push"]).methods[0]?.input).toBe("push");
  });

  test("carries the banner and error copy the client renders", () => {
    const ui = stepUpUi(["totp"]);
    expect(ui.banner.title && ui.banner.expiredDescription && ui.banner.action).toBeTruthy();
    expect(ui.messages.invalid_code && ui.messages.rate_limited && ui.messages.record_failed).toBeTruthy();
  });
});
