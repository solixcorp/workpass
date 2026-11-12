/**
 * Admin-controlled runtime settings. The registry is the single definition of
 * what can be changed: type, allowed range, default and the Korean copy the
 * admin screen renders. Anything not listed here cannot be stored.
 *
 * Secrets (keys, tokens, signing material) and boot-time switches never belong
 * here: they stay in the Worker environment. A stored value overrides the
 * environment variable named by `envName`; with nothing stored the
 * environment value applies, then `default`.
 */

import type { Env } from "../env";

export type SettingGroup = "organization" | "login" | "mfa" | "device-risk" | "step-up" | "activation";

interface BaseDefinition {
  key: string;
  envName: keyof Env & string;
  group: SettingGroup;
  label: string;
  description: string;
  default: string;
}

export type SettingDefinition =
  | (BaseDefinition & { type: "enum"; options: Array<{ value: string; label: string }> })
  | (BaseDefinition & { type: "int"; min: number; max: number; unit?: string })
  | (BaseDefinition & { type: "number"; min: number; max: number; step: number })
  | (BaseDefinition & { type: "text"; maxLength: number });

export const SETTING_GROUPS: Record<SettingGroup, { label: string; description: string }> = {
  organization: {
    label: "조직",
    description: "로그인 화면과 콘솔에 표시되는 조직 정보입니다.",
  },
  login: {
    label: "로그인 방식",
    description: "로그인 화면에서 쓸 수 있는 방식입니다.",
  },
  mfa: {
    label: "2차 인증",
    description: "누가 2차 인증을 써야 하는지, 어떤 방식을 허용할지 정합니다.",
  },
  "device-risk": {
    label: "기기 위험도 (Fingerprint)",
    description: "로그인할 때 기기를 확인하는 방식입니다.",
  },
  "step-up": {
    label: "추가 인증",
    description: "위험하다고 판단된 로그인에 요구하는 2차 인증입니다.",
  },
  activation: {
    label: "계정 활성화",
    description: "처음 비밀번호를 설정하는 링크입니다.",
  },
};

export const DEFAULT_ORGANIZATION_NAME = "Solixcorp";

export const SETTINGS: SettingDefinition[] = [
  {
    key: "organization.name",
    envName: "ORGANIZATION_NAME",
    group: "organization",
    type: "text",
    label: "조직 이름",
    description: "로그인 카드 맨 위와 콘솔 사이드바에 표시됩니다.",
    default: DEFAULT_ORGANIZATION_NAME,
    maxLength: 64,
  },
  {
    key: "login.allow_passkey",
    envName: "LOGIN_ALLOW_PASSKEY",
    group: "login",
    type: "enum",
    label: "패스키",
    description: "사용 안 함으로 두면 로그인 화면과 보안 페이지에서 패스키가 사라지고 서버도 거절합니다.",
    default: "on",
    options: [
      { value: "on", label: "허용" },
      { value: "off", label: "사용 안 함" },
    ],
  },
  {
    key: "mfa.require",
    envName: "MFA_REQUIRE",
    group: "mfa",
    type: "enum",
    label: "2차 인증 필수 대상",
    description: "필수 대상은 로그인할 때마다 2차 인증을 하고, 등록하지 않았다면 포털에서 등록 화면으로 보냅니다.",
    default: "off",
    options: [
      { value: "off", label: "필수 아님" },
      { value: "admins", label: "관리자만" },
      { value: "everyone", label: "모든 사용자" },
    ],
  },
  {
    key: "mfa.allow_totp",
    envName: "MFA_ALLOW_TOTP",
    group: "mfa",
    type: "enum",
    label: "인증 앱 (TOTP)",
    description: "끄면 새로 등록할 수 없고, 이미 등록한 계정도 이 방식으로 인증할 수 없습니다.",
    default: "on",
    options: [
      { value: "on", label: "허용" },
      { value: "off", label: "사용 안 함" },
    ],
  },
  {
    key: "mfa.allow_otp",
    envName: "MFA_ALLOW_OTP",
    group: "mfa",
    type: "enum",
    label: "일회용 코드 (메일/SMS)",
    description: "끄면 새로 켤 수 없고, 로그인 때도 쓸 수 없습니다.",
    default: "on",
    options: [
      { value: "on", label: "허용" },
      { value: "off", label: "사용 안 함" },
    ],
  },
  {
    key: "mfa.allow_hotp",
    envName: "MFA_ALLOW_HOTP",
    group: "mfa",
    type: "enum",
    label: "하드웨어 토큰 (HOTP)",
    description: "끄면 새 토큰을 등록할 수 없고, 등록된 토큰으로도 인증할 수 없습니다.",
    default: "on",
    options: [
      { value: "on", label: "허용" },
      { value: "off", label: "사용 안 함" },
    ],
  },
  {
    key: "mfa.allow_duo",
    envName: "MFA_ALLOW_DUO",
    group: "mfa",
    type: "enum",
    label: "Duo 푸시",
    description: "Duo 연동 키가 설정된 배포에서만 의미가 있습니다.",
    default: "on",
    options: [
      { value: "on", label: "허용" },
      { value: "off", label: "사용 안 함" },
    ],
  },
  {
    key: "fingerprint.mode",
    envName: "FINGERPRINT_MODE",
    group: "device-risk",
    type: "enum",
    label: "동작 방식",
    description: "기기 확인은 항상 실행됩니다(서버 키가 있을 때). 관찰: 기록만 하고 막지 않음. 강제: 위험하면 막거나 추가 인증을 요구함. '끔'은 관찰로 취급됩니다.",
    default: "observe",
    options: [
      { value: "disabled", label: "끔" },
      { value: "observe", label: "관찰" },
      { value: "enforce", label: "강제" },
    ],
  },
  {
    key: "fingerprint.min_confidence",
    envName: "FINGERPRINT_MIN_CONFIDENCE",
    group: "device-risk",
    type: "number",
    label: "최소 기기 신뢰도",
    description: "이 값보다 낮게 식별된 기기는 위험으로 봅니다. 0에서 1 사이입니다.",
    default: "0.7",
    min: 0,
    max: 1,
    step: 0.05,
  },
  {
    key: "fingerprint.max_event_age_seconds",
    envName: "FINGERPRINT_MAX_EVENT_AGE_SECONDS",
    group: "device-risk",
    type: "int",
    label: "확인 결과 유효 시간",
    description: "기기 확인 결과를 로그인에 쓸 수 있는 최대 시간입니다.",
    default: "120",
    min: 30,
    max: 600,
    unit: "초",
  },
  {
    key: "step_up.challenge_ttl_seconds",
    envName: "STEP_UP_CHALLENGE_TTL_SECONDS",
    group: "step-up",
    type: "int",
    label: "추가 인증 제한 시간",
    description: "추가 인증이 요구된 뒤 이 시간 안에 끝내야 합니다.",
    default: "900",
    min: 300,
    max: 3600,
    unit: "초",
  },
  {
    key: "activation.token_ttl_minutes",
    envName: "ACTIVATION_TOKEN_TTL_MINUTES",
    group: "activation",
    type: "int",
    label: "활성화 링크 유효 시간",
    description: "관리자가 보낸 활성화 링크가 열려 있는 시간입니다.",
    default: "1440",
    min: 5,
    max: 4320,
    unit: "분",
  },
];

const BY_KEY = new Map(SETTINGS.map((definition) => [definition.key, definition]));

export function settingDefinition(key: string): SettingDefinition | null {
  return BY_KEY.get(key) ?? null;
}

export function organizationName(env: Env): string {
  return env.ORGANIZATION_NAME?.trim() || DEFAULT_ORGANIZATION_NAME;
}

/** Validate and normalize a submitted value; throws a message safe to show. */
export function normalizeSettingValue(definition: SettingDefinition, raw: unknown): string {
  if (definition.type === "text") {
    const text = typeof raw === "string" ? raw.trim() : "";
    // eslint-disable-next-line no-control-regex
    if (text.length === 0 || text.length > definition.maxLength || /[\u0000-\u001f\u007f]/.test(text)) {
      throw new Error(`1자에서 ${definition.maxLength}자 사이의 이름을 입력하세요.`);
    }
    return text;
  }
  if (definition.type === "enum") {
    if (typeof raw === "string" && definition.options.some((option) => option.value === raw)) return raw;
    throw new Error("허용되지 않은 값입니다.");
  }
  const text = typeof raw === "number" ? String(raw) : typeof raw === "string" ? raw.trim() : "";
  const value = text === "" ? Number.NaN : Number(text);
  if (!Number.isFinite(value) || value < definition.min || value > definition.max) {
    throw new Error(`${definition.min}에서 ${definition.max} 사이의 값을 입력하세요.`);
  }
  if (definition.type === "int" && !Number.isInteger(value)) {
    throw new Error("정수를 입력하세요.");
  }
  return String(value);
}
