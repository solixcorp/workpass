/**
 * Second-factor enrollment surface for the signed-in user.
 *
 *   GET    /api/mfa/enrollment   -> the enrollment screen definition and current state
 *   DELETE /api/mfa/hotp/:id     -> remove one of the user's own hardware tokens
 *
 * The browser runs the actual enrollment protocols against Better Auth
 * (authenticator app, one-time codes, backup codes) and /api/mfa/hotp/enroll;
 * everything it shows (titles, method names, hints, which actions exist) is
 * defined here so the administrator's policy decides what a user can do.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { auditStandaloneOperation } from "../audit/store";
import { duoConfig } from "./duo";
import { isSmsOtpAvailable } from "./otp-senders";
import { mfaPolicy, userMustUseMfa, workpassMfaRequired } from "./policy";
import { usableSecondFactors } from "../security/step-up";

export const mfaEnrollRoutes = new Hono<{ Bindings: Env }>();

type MethodState = "enrolled" | "available" | "blocked" | "unconfigured";

interface MethodView {
  key: "totp" | "otp" | "hotp" | "duo";
  label: string;
  description: string;
  state: MethodState;
  stateLabel: string;
  /** What the user can do with this method right now. */
  actions: Array<"enroll" | "add" | "remove">;
}

const STATE_LABEL: Record<MethodState, string> = {
  enrolled: "사용 중",
  available: "등록 가능",
  blocked: "관리자가 막음",
  unconfigured: "준비되지 않음",
};

export interface EnrollmentView {
  title: string;
  description: string;
  required: boolean;
  /** The user has to enroll before anything else: required, with no factor yet. */
  mustEnroll: boolean;
  enabled: boolean;
  /** The account still holds a server-side password, which Better Auth asks for on enable/disable. */
  passwordRequired: boolean;
  passwordLabel: string;
  requiredNotice: string;
  methods: MethodView[];
  /** The card shown during sign-in when a required second factor is not set up yet. */
  signIn: { title: string; description: string; requiredHeading: string; hint: string; setup: string; back: string };
  hotpTokens: Array<{ id: string; label: string; createdAt: string }>;
  backupCodes: { available: boolean; label: string; description: string };
  disable: { available: boolean; label: string; description: string; blockedReason?: string };
  labels: Record<string, string>;
}

export async function buildEnrollmentView(
  env: Env,
  user: { id: string; role?: unknown; twoFactorEnabled?: unknown },
): Promise<EnrollmentView> {
  const policy = mfaPolicy(env);
  const twoFactorEnabled = user.twoFactorEnabled === true || user.twoFactorEnabled === 1;
  const secret = await env.DB.prepare('SELECT verified FROM "twoFactor" WHERE userId = ? LIMIT 1')
    .bind(user.id).first<{ verified: number | boolean | null }>().catch(() => null);
  const hasTotp = twoFactorEnabled && secret !== null && secret.verified !== 0 && secret.verified !== false;
  const tokens = await env.DB.prepare(
    "SELECT id, label, created_at AS createdAt FROM mfa_hotp_tokens WHERE user_id = ? ORDER BY created_at ASC LIMIT 20",
  ).bind(user.id).all<{ id: string; label: string; createdAt: string }>().catch(() => ({ results: [] }));
  const phone = await env.DB.prepare("SELECT phoneNumber FROM phone_number WHERE userId = ? LIMIT 1")
    .bind(user.id).first().catch(() => null);
  const smsDelivery = Boolean(phone) && isSmsOtpAvailable(env);

  const pick = (allowed: boolean, enrolled: boolean, ready = true): MethodState =>
    !allowed ? "blocked" : enrolled ? "enrolled" : ready ? "available" : "unconfigured";

  const methods: MethodView[] = [
    {
      key: "totp",
      label: "인증 앱",
      description: "Google Authenticator, Microsoft Authenticator 같은 앱에서 6자리 코드를 만듭니다.",
      state: pick(policy.allow.totp, hasTotp),
      stateLabel: "",
      actions: policy.allow.totp && !hasTotp ? ["enroll"] : [],
    },
    {
      key: "otp",
      label: "일회용 코드",
      description: (smsDelivery
        ? "등록된 휴대폰 번호로 문자 메시지를 보냅니다."
        : "계정 이메일로 일회용 코드를 보냅니다.") +
        (hasTotp ? " 인증 앱을 등록하면 함께 켜집니다." : ""),
      state: pick(policy.allow.otp, twoFactorEnabled),
      stateLabel: "",
      actions: policy.allow.otp && !twoFactorEnabled ? ["enroll"] : [],
    },
    {
      key: "hotp",
      label: "보안 토큰",
      description: "버튼을 누르면 6자리 코드를 보여주는 하드웨어 토큰입니다. 등록 후 토큰을 눌러 나온 코드를 입력합니다.",
      state: pick(policy.allow.hotp, tokens.results.length > 0),
      stateLabel: "",
      actions: policy.allow.hotp ? ["add"] : [],
    },
    {
      key: "duo",
      label: "Duo 푸시",
      description: "휴대폰의 Duo 앱으로 승인 요청을 받습니다. Duo 앱에 같은 이메일로 등록돼 있어야 합니다.",
      state: policy.allow.duo ? (duoConfig(env) ? "available" : "unconfigured") : "blocked",
      stateLabel: "",
      actions: [],
    },
  ];
  for (const method of methods) method.stateLabel = STATE_LABEL[method.state];

  const credential = await env.DB.prepare(
    "SELECT password FROM account WHERE userId = ? AND providerId = 'credential' LIMIT 1",
  ).bind(user.id).first<{ password: string | null }>().catch(() => null);
  const required = await workpassMfaRequired(env, user);
  const factors = await usableSecondFactors(env, user.id);
  const enabled = factors.length > 0;
  const mustEnrollNow = userMustUseMfa(env, user) || required;
  const locked = userMustUseMfa(env, user);

  return {
    title: "2차 인증",
    description: "비밀번호가 알려져도 계정을 지킵니다. 쓸 수 있는 방식을 하나 이상 등록하세요.",
    required: mustEnrollNow,
    mustEnroll: mustEnrollNow && !enabled,
    enabled,
    passwordRequired: Boolean(credential?.password),
    passwordLabel: "계정 비밀번호",
    requiredNotice: "관리자가 이 계정에 2차 인증을 필수로 정했습니다. 등록을 마쳐야 앱을 열 수 있습니다.",
    methods,
    signIn: {
      title: "보안 방법 설정",
      description: "보안 방법은 사용자 본인만 접근할 수 있도록 계정을 보호합니다.",
      requiredHeading: "지금 요구됨",
      hint: "아래 방법 중 하나를 설정하면 로그인을 계속할 수 있습니다.",
      setup: "설정",
      back: "로그인으로 돌아가기",
    },
    hotpTokens: tokens.results,
    backupCodes: {
      available: hasTotp,
      label: "백업 코드 다시 받기",
      description: "휴대폰을 잃어버렸을 때 한 번씩 쓸 수 있는 코드입니다. 새로 받으면 이전 코드는 쓸 수 없습니다.",
    },
    disable: {
      available: twoFactorEnabled && !locked,
      label: "인증 앱과 일회용 코드 끄기",
      description: "인증 앱, 일회용 코드, 백업 코드를 모두 끕니다. 보안 토큰은 따로 삭제합니다.",
      ...(locked && twoFactorEnabled ? { blockedReason: "관리자가 2차 인증을 필수로 정해서 끌 수 없습니다." } : {}),
    },
    labels: {
      enroll: "등록",
      add: "추가",
      remove: "삭제",
      verify: "확인",
      copy: "복사",
      done: "완료",
      totpScan: "인증 앱으로 QR 코드를 스캔하세요",
      totpManual: "스캔할 수 없다면 이 키를 직접 입력하세요",
      totpVerify: "앱에 표시된 6자리 코드를 입력하세요",
      backupTitle: "백업 코드를 저장하세요",
      backupBody: "각 코드는 한 번만 쓸 수 있고, 이 화면을 닫으면 다시 볼 수 없습니다.",
      hotpName: "토큰 이름",
      hotpSecret: "토큰 키 (Base32)",
      hotpVerify: "토큰을 눌러 나온 6자리 코드",
      otpEnabled: "일회용 코드를 켰습니다.",
    },
  };
}

mfaEnrollRoutes.get("/mfa/enrollment", async (context) => {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  context.header("Cache-Control", "no-store");
  return context.json(await buildEnrollmentView(context.env, session.user as never));
});

mfaEnrollRoutes.delete("/mfa/hotp/:id", async (context) => {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  if (context.req.header("origin") !== new URL(context.env.AUTH_BASE_URL).origin) {
    return context.json({ error: "Invalid origin" }, 403);
  }
  const id = context.req.param("id");
  const user = session.user as { id: string; role?: unknown };
  return auditStandaloneOperation(context.env, "mfa.hotp.remove", `/api/mfa/hotp/${id}`, async () => {
    // Removing the last factor of a required account would lock it out of enrollment state.
    const remaining = await usableSecondFactors(context.env, user.id);
    const ownsOnlyThis = remaining.length === 1 && remaining[0] === "hotp";
    if (userMustUseMfa(context.env, user) && ownsOnlyThis) {
      return { response: context.json({ error: "필수 2차 인증의 마지막 수단은 삭제할 수 없습니다." }, 409), actorUserId: user.id };
    }
    const result = await context.env.DB.prepare("DELETE FROM mfa_hotp_tokens WHERE id = ? AND user_id = ?")
      .bind(id, user.id).run();
    return {
      response: result.meta.changes === 1 ? context.json({ removed: true }) : context.json({ error: "토큰을 찾을 수 없습니다." }, 404),
      actorUserId: user.id,
    };
  });
});
