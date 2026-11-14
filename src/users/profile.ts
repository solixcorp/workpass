/** The profile fields an administrator keeps for a user, beyond name and e-mail. */

import type { Env } from "../env";

export interface ProfileField {
  key: string;
  label: string;
  group: "identity" | "work" | "contact" | "locale";
}

export const PROFILE_FIELDS: ProfileField[] = [
  { key: "displayName", label: "표시 이름", group: "identity" },
  { key: "nickName", label: "별명", group: "identity" },
  { key: "honorificPrefix", label: "호칭(앞)", group: "identity" },
  { key: "honorificSuffix", label: "호칭(뒤)", group: "identity" },
  { key: "profileUrl", label: "프로필 주소", group: "identity" },
  { key: "title", label: "직함", group: "work" },
  { key: "userType", label: "사용자 유형", group: "work" },
  { key: "employeeNumber", label: "사번", group: "work" },
  { key: "costCenter", label: "코스트 센터", group: "work" },
  { key: "organization", label: "조직", group: "work" },
  { key: "division", label: "본부", group: "work" },
  { key: "department", label: "부서", group: "work" },
  { key: "managerId", label: "관리자 ID", group: "work" },
  { key: "manager", label: "관리자", group: "work" },
  { key: "secondEmail", label: "보조 이메일", group: "contact" },
  { key: "primaryPhone", label: "대표 전화", group: "contact" },
  { key: "streetAddress", label: "주소", group: "contact" },
  { key: "city", label: "시", group: "contact" },
  { key: "state", label: "도", group: "contact" },
  { key: "zipCode", label: "우편번호", group: "contact" },
  { key: "countryCode", label: "국가 코드", group: "contact" },
  { key: "postalAddress", label: "우편 주소", group: "contact" },
  { key: "preferredLanguage", label: "선호 언어", group: "locale" },
  { key: "locale", label: "로케일", group: "locale" },
  { key: "timezone", label: "시간대", group: "locale" },
];

const KEYS = new Set(PROFILE_FIELDS.map((field) => field.key));
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;

export async function readProfile(env: Env, userId: string): Promise<Record<string, string>> {
  try {
    const row = await env.DB.prepare("SELECT data FROM user_profiles WHERE user_id = ?").bind(userId).first<{ data: string }>();
    const parsed: unknown = row ? JSON.parse(row.data) : {};
    return parsed && typeof parsed === "object" ? (parsed as Record<string, string>) : {};
  } catch {
    return {};
  }
}

export interface ProfileUpdate {
  name?: string;
  phoneNumber?: string | null;
  fields?: Record<string, string>;
}

/** Checks a profile update; the message is shown to the person who sent it. */
export function validateProfile(body: unknown): ProfileUpdate | { error: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: "요청 형식이 올바르지 않습니다." };
  const value = body as Record<string, unknown>;
  const out: ProfileUpdate = {};
  if (value.name !== undefined) {
    if (typeof value.name !== "string" || !value.name.trim() || value.name.trim().length > 128 || CONTROL.test(value.name)) {
      return { error: "이름은 1자에서 128자 사이여야 합니다." };
    }
    out.name = value.name.trim();
  }
  if (value.phoneNumber !== undefined) {
    if (value.phoneNumber === null || value.phoneNumber === "") out.phoneNumber = null;
    else if (typeof value.phoneNumber === "string" && /^010\d{8}$/.test(value.phoneNumber.replace(/[\s-]/g, ""))) out.phoneNumber = value.phoneNumber.replace(/[\s-]/g, "");
    else return { error: "휴대전화 번호는 01012345678처럼 010으로 시작하는 숫자 11자리로 넣으세요." };
  }
  if (value.fields !== undefined) {
    if (!value.fields || typeof value.fields !== "object" || Array.isArray(value.fields)) return { error: "프로필 항목 형식이 올바르지 않습니다." };
    const fields: Record<string, string> = {};
    for (const [key, raw] of Object.entries(value.fields as Record<string, unknown>)) {
      if (!KEYS.has(key)) return { error: `알 수 없는 항목입니다: ${key}` };
      if (raw === null || raw === "") { fields[key] = ""; continue; }
      if (typeof raw !== "string" || raw.length > 256 || CONTROL.test(raw)) return { error: "항목 값은 256자 이하의 글자여야 합니다." };
      fields[key] = raw.trim();
    }
    if (fields.secondEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.secondEmail)) return { error: "보조 이메일 형식이 올바르지 않습니다." };
    if (fields.profileUrl && !/^https:\/\/\S+$/.test(fields.profileUrl)) return { error: "프로필 주소는 https 주소여야 합니다." };
    out.fields = fields;
  }
  return out;
}
