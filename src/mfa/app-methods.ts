import type { Env } from "../env";
import { mfaPolicy, passkeyAllowed } from "./policy";
import { transactionEmailAvailable } from "../mail/send";
import { smsAvailable } from "../sms/provider";

export const APP_MFA_METHODS = ["totp", "hotp", "duo", "passkey", "email", "sms"] as const;
export type AppMfaMethod = typeof APP_MFA_METHODS[number];

export async function availableAppMfaMethods(env: Env) {
  const allow = mfaPolicy(env).allow;
  const { workpassClientId } = await import("../auth/workpass");
  const { loadAppAccessPolicy } = await import("../access/policies");
  const workpass = await loadAppAccessPolicy(env, `oidc:${await workpassClientId(env)}`).catch(() => null);
  const passkeyEnabled = passkeyAllowed(env) && (workpass?.allowedMethods ?? "password,passkey").split(",").some((method) => method.trim() === "passkey");
  return [
    { id: "totp", label: "인증 앱(TOTP)", enabledGlobally: allow.totp },
    { id: "hotp", label: "보안 토큰(HOTP)", enabledGlobally: allow.hotp },
    { id: "duo", label: "Duo", enabledGlobally: allow.duo },
    { id: "passkey", label: "패스키", enabledGlobally: passkeyEnabled },
    { id: "email", label: "이메일 코드", enabledGlobally: allow.otp && transactionEmailAvailable(env) },
    { id: "sms", label: "문자(SMS) 코드", enabledGlobally: allow.otp && smsAvailable(env) },
  ];
}
