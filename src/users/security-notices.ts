import type { Env } from "../env";
import { notifySecurity, type Notice } from "./notifications";

const password: Notice = { kind: "security_password", title: "비밀번호가 변경되었습니다", body: "본인이 변경한 것이 아니라면 관리자에게 알려주세요.", link: "/security" };
const enrolled: Notice = { kind: "security_mfa", title: "2차 인증 수단이 등록되었습니다", body: "보안 설정에서 인증 수단을 확인하세요.", link: "/security" };
const removed: Notice = { kind: "security_mfa", title: "2차 인증 수단이 삭제되었습니다", body: "보안 설정에서 인증 수단을 확인하세요.", link: "/security" };
const account = (title: string): Notice => ({ kind: "security_account", title, body: "보안 설정에서 계정 상태를 확인하세요.", link: "/security" });

const notices: Record<string, Notice> = {
  "opaque.register.finish": password,
  "identity.user.password_change.success_or_failure": password,
  "identity.user.password_reset.success_or_failure": password,
  "identity.user.account_recovery": password,
  "mfa.hotp.enroll": enrolled,
  "mfa.hotp.admin_attach": enrolled,
  "mfa.hotp.remove": removed,
  "mfa.hotp.admin_remove": removed,
  "mfa.admin_reset": removed,
  "authentication.passkey.registration.success_or_failure": enrolled,
  "identity.user.disable.success_or_failure": account("계정이 비활성화되었습니다"),
  "identity.user.enable.success_or_failure": account("계정이 활성화되었습니다"),
  "identity.user.role_change.success_or_failure": account("계정 역할이 변경되었습니다"),
  "identity.user.sessions_revoke.success_or_failure": account("모든 세션이 해제되었습니다"),
  "identity.user.trusted_devices.revoke": account("신뢰 기기가 해제되었습니다"),
  "identity.user.lockdown": account("계정이 잠겼습니다"),
  "identity.user.lockdown_lifted": account("계정 잠금이 해제되었습니다"),
};

export async function notifySecurityEvent(env: Env, eventType: string, userId: string | null): Promise<void> {
  const notice = notices[eventType];
  if (notice && userId) await notifySecurity(env, userId, notice);
}

export { enrolled as mfaEnrolledNotice, removed as mfaRemovedNotice };
