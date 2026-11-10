/**
 * The password policy family (docs/authentik-policies design): complexity
 * (with a HIBP range check and an embedded lightweight strength estimator),
 * expiry (with deny-only mode), and reuse prevention through a digest history.
 */

import type { Env } from "../env";

export interface PasswordPolicyConfig {
  minLength: number;
  minUpper: number;
  minLower: number;
  minDigit: number;
  minSymbol: number;
  symbolSet: string;
  checkHibp: boolean;
  checkStrength: boolean;
  minScore: number;
  passwordField: string;
}

export interface PasswordExpiryConfig {
  days: number;
  denyOnly: boolean;
}

export interface PasswordUniquenessConfig {
  count: number;
  passwordField: string;
}

const DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";

export function validatePasswordConfig(config: unknown): PasswordPolicyConfig {
  const value = (config ?? {}) as Record<string, unknown>;
  const numberInRange = (key: string, min: number, max: number, fallback: number): number => {
    const raw = value[key];
    if (raw === undefined) return fallback;
    if (typeof raw !== "number" || !Number.isInteger(raw) || raw < min || raw > max) {
      throw new Error(`${key} must be an integer between ${min} and ${max}`);
    }
    return raw;
  };
  return {
    minLength: numberInRange("minLength", 8, 512, 12),
    minUpper: numberInRange("minUpper", 0, 64, 1),
    minLower: numberInRange("minLower", 0, 64, 1),
    minDigit: numberInRange("minDigit", 0, 64, 1),
    minSymbol: numberInRange("minSymbol", 0, 64, 0),
    symbolSet: typeof value.symbolSet === "string" && value.symbolSet.length > 0
      ? value.symbolSet : DEFAULT_SYMBOLS,
    checkHibp: value.checkHibp === true,
    checkStrength: value.checkStrength === true,
    minScore: numberInRange("minScore", 0, 4, 2),
    passwordField: typeof value.passwordField === "string" && value.passwordField.length > 0
      ? value.passwordField.slice(0, 64) : "password",
  };
}

export function validateExpiryConfig(config: unknown): PasswordExpiryConfig {
  const value = (config ?? {}) as Record<string, unknown>;
  const days = typeof value.days === "number" && Number.isInteger(value.days) && value.days >= 1 && value.days <= 3650
    ? value.days : 180;
  return { days, denyOnly: value.denyOnly === true };
}

export function validateUniquenessConfig(config: unknown): PasswordUniquenessConfig {
  const value = (config ?? {}) as Record<string, unknown>;
  const count = typeof value.count === "number" && Number.isInteger(value.count) && value.count >= 1 && value.count <= 32
    ? value.count : 5;
  return {
    count,
    passwordField: typeof value.passwordField === "string" && value.passwordField.length > 0
      ? value.passwordField.slice(0, 64) : "password",
  };
}

// --- lightweight strength estimator -----------------------------------------

const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "abc123", "111111", "123456789",
  "password1", "123123", "iloveyou", "admin", "welcome", "monkey", "dragon",
  "sunshine", "princess", "football", "baseball", "superman", "letmein",
  "qwerty123", "password123", "1q2w3e4r", "qazwsx", "1234qwer", "asdfgh",
  "654321", "555555", "lovely", "charlie", "joshua", "hunter", "summer",
  "master", "freedom", "whatever", "trustno1", "starwars", "hello123",
  "google", "internet", "service", "canada", "hello", "ranger", "shadow",
  "michael", "matrix", "cheese", "ninja", "azerty", "solo", "test123",
]);

const KEYBOARD_ROWS = [
  "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
  "qazwsx", "1qaz2wsx", "zaq1", "qwaszx", "poiuy", "1234qwer",
];

function leetNormalize(text: string): string {
  return text
    .replace(/[@4]/gi, "a").replace(/8/gi, "b").replace(/[({]/g, "c")
    .replace(/3/gi, "e").replace(/6/gi, "g").replace(/1|!/gi, "l")
    .replace(/0/gi, "o").replace(/[$5]/gi, "s").replace(/7/gi, "t");
}

export interface StrengthSignals {
  repeatedRuns: number;
  sequentialRuns: number;
  keyboardRuns: number;
  commonHit: boolean;
  classes: number;
}

export function strengthSignals(password: string): StrengthSignals {
  const lowered = leetNormalize(password.toLowerCase());
  let classes = (["a-z", "A-Z", "0-9"] as const)
    .filter((range) => new RegExp(`[${range}]`).test(password)).length;
  if (/[^A-Za-z0-9]/.test(password)) classes += 1;
  return {
    repeatedRuns: countRepeatedRuns(password),
    sequentialRuns: countSequentialRuns(lowered),
    keyboardRuns: countKeyboardRuns(lowered),
    commonHit: COMMON_PASSWORDS.has(lowered) || COMMON_PASSWORDS.has(password.toLowerCase()),
    classes,
  };
}

function countRepeatedRuns(password: string): number {
  let runs = 0;
  for (let i = 0; i + 3 <= password.length; i += 1) {
    if (password[i] === password[i + 1] && password[i + 1] === password[i + 2]) {
      runs += 1; i += 2;
    }
  }
  return runs;
}

function countSequentialRuns(lowered: string): number {
  let runs = 0;
  for (const alphabet of ["abcdefghijklmnopqrstuvwxyz", "0123456789"]) {
    for (let i = 0; i + 4 <= alphabet.length; i += 1) {
      const forward = alphabet.slice(i, i + 4);
      if (lowered.includes(forward) || lowered.includes([...forward].reverse().join(""))) {
        runs += 1; i += 3;
      }
    }
  }
  return runs;
}

function countKeyboardRuns(lowered: string): number {
  let runs = 0;
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i + 4 <= row.length; i += 1) {
      const chunk = row.slice(i, i + 4);
      if (lowered.includes(chunk) || lowered.includes([...chunk].reverse().join(""))) {
        runs += 1; i += 3;
      }
    }
  }
  return runs;
}

/**
 * A 0–4 strength score: an entropy-driven length/class baseline minus
 * penalties for repeated runs, sequences, keyboard patterns and common
 * passwords. Deliberately lightweight (no full dictionary beyond common
 * entries); never rejects by itself — the policy's minScore does.
 */
export function estimateStrength(password: string): number {
  const signals = strengthSignals(password);
  if (signals.commonHit) return 0;
  const charset = signals.classes === 0 ? 26
    : signals.classes === 1 ? 10 : signals.classes === 2 ? 62 : signals.classes === 3 ? 80 : 95;
  const entropy = password.length * (Math.log2(charset) || 1);
  let score = entropy >= 95 ? 4 : entropy >= 70 ? 3 : entropy >= 50 ? 2 : entropy >= 35 ? 1 : 0;
  for (
    let penalties = signals.repeatedRuns + signals.sequentialRuns + signals.keyboardRuns;
    penalties > 0;
    penalties -= 2
  ) {
    score -= 1;
  }
  return Math.max(0, Math.min(4, score));
}

// --- HIBP -------------------------------------------------------------------

export async function hibpExposureCount(password: string): Promise<number> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  const prefix = hex.slice(0, 5);
  const suffix = hex.slice(5);
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "add-padding": "1" },
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`HIBP range lookup failed with status ${response.status}`);
  const body = await response.text();
  for (const line of body.split("\n")) {
    const [suffixPart, countPart] = line.trim().split(":");
    if (suffixPart === suffix) return Number(countPart ?? 0);
  }
  return 0;
}

// --- complexity + HIBP + strength validation --------------------------------

export interface PasswordValidationResult {
  passing: boolean;
  messages: string[];
}

export async function validatePasswordComplexity(
  password: string,
  config: PasswordPolicyConfig,
): Promise<PasswordValidationResult> {
  const messages: string[] = [];
  if (password.length < config.minLength) {
    messages.push(`the password must be at least ${config.minLength} characters`);
  }
  if ((password.match(/[A-Z]/g) ?? []).length < config.minUpper) {
    messages.push(`the password needs at least ${config.minUpper} uppercase characters`);
  }
  if ((password.match(/[a-z]/g) ?? []).length < config.minLower) {
    messages.push(`the password needs at least ${config.minLower} lowercase characters`);
  }
  if ((password.match(/[0-9]/g) ?? []).length < config.minDigit) {
    messages.push(`the password needs at least ${config.minDigit} digits`);
  }
  const symbolSet = config.symbolSet.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const symbolMatches = password.match(new RegExp(`[${symbolSet}]`, "g")) ?? [];
  if (symbolMatches.length < config.minSymbol) {
    messages.push(`the password needs at least ${config.minSymbol} symbols`);
  }
  if (config.checkHibp) {
    const count = await hibpExposureCount(password).catch(() => -1);
    if (count < 0) {
      return { passing: false, messages: [...messages, "the password could not be checked for exposure; try again"] };
    }
    if (count > 0) messages.push("the password appears in known data breaches");
  }
  if (config.checkStrength && estimateStrength(password) < config.minScore) {
    messages.push("the password is too weak (repeated, sequential or common patterns)");
  }
  return { passing: messages.length === 0, messages };
}

// --- metadata and history ---------------------------------------------------

export interface PasswordMeta {
  userId: string;
  changedAt: string;
  unusable: boolean;
}

export async function recordPasswordChange(env: Env, userId: string): Promise<void> {
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO password_meta (user_id, changed_at, unusable) VALUES (?, ?, 0)
     ON CONFLICT (user_id) DO UPDATE SET changed_at = excluded.changed_at, unusable = 0`,
  ).bind(userId, now).run();
}

export async function getPasswordMeta(env: Env, userId: string): Promise<PasswordMeta | null> {
  const row = await env.DB.prepare(
    "SELECT user_id AS userId, changed_at AS changedAt, unusable FROM password_meta WHERE user_id = ? LIMIT 1",
  ).bind(userId).first<{ userId: string; changedAt: string; unusable: number }>();
  if (!row) return null;
  return { userId: row.userId, changedAt: row.changedAt, unusable: row.unusable === 1 };
}

export async function markPasswordUnusable(env: Env, userId: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO password_meta (user_id, changed_at, unusable) VALUES (?, ?, 1)
     ON CONFLICT (user_id) DO UPDATE SET unusable = 1`,
  ).bind(userId, new Date().toISOString()).run();
}

const HISTORY_PRUNE_LIMIT = 32;

/**
 * Append the candidate password into the per-user reuse history (PBKDF2
 * digest per entry, one salt each), pruning to the cap. Never stores the
 * plaintext or a login-capable hash format.
 */
export async function passwordHistoryAppend(env: Env, userId: string, password: string): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const digest = await pbkdf2(password, salt);
  await env.DB.prepare(
    `INSERT INTO password_history (user_id, salt, digest, created_at)
     VALUES (?, ?, ?, ?)`,
  ).bind(userId, toHex(salt), toHex(digest), new Date().toISOString()).run();
  await env.DB.prepare(
    `DELETE FROM password_history WHERE user_id = ? AND created_at NOT IN (
       SELECT created_at FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ${HISTORY_PRUNE_LIMIT}
     )`,
  ).bind(userId, userId).run();
}

async function pbkdf2(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: 20_000 },
    key, 128,
  );
  return new Uint8Array(bits);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) mismatch |= a[i]! ^ b[i]!;
  return mismatch === 0;
}

/** Whether the candidate matches one of the stored history digests. */
export async function passwordHistoryContains(env: Env, userId: string, password: string, count: number): Promise<boolean> {
  const rows = await env.DB.prepare(
    `SELECT salt, digest FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
  ).bind(userId, count).all<{ salt: string; digest: string }>();
  for (const row of rows.results) {
    const candidate = await pbkdf2(password, fromHex(row.salt));
    if (timingSafeEqual(candidate, fromHex(row.digest))) return true;
  }
  return false;
}
