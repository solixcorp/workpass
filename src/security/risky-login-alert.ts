import type { Env } from "../env";
import { sendTransactionEmail } from "../mail/send";
import { sendSms, smsAvailable } from "../sms/provider";
import { describeDevice } from "../users/device";
import { notifyUser } from "../users/notifications";

/** Verdicts that block a sign-in outright; the account owner is told about these. */
const BLOCKING_REASONS = ["bot_detected", "tampering_detected", "tor_network_detected", "ip_blocklisted"] as const;
const NOTICE_KIND = "risky_login_blocked";
const ALERT_WINDOW_MS = 60 * 60 * 1000;
const ALERTS_PER_DAY = 5;

export function isBlockingRisk(reasons: readonly string[]): boolean {
  return reasons.some((reason) => (BLOCKING_REASONS as readonly string[]).includes(reason));
}

function countryName(code: string | null): string {
  if (!code) return "";
  if (code === "KR") return "Korea";
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

export interface AlertContext {
  ip: string;
  place: string;
  device: string;
  when: string;
}

/** `Seoul, Korea` / `MacOS, Chrome`: the short forms shown in the message. */
export function describeAttempt(request: Request, now = new Date()): AlertContext {
  const cf = ((request as Request & { cf?: Record<string, unknown> }).cf ?? {}) as { city?: string; country?: string };
  const ip = (request.headers.get("cf-connecting-ip") ?? "").slice(0, 64) || "알 수 없음";
  const place = [cf.city, countryName(cf.country ?? null)].filter(Boolean).join(", ") || "알 수 없음";
  const { os, browser } = describeDevice(request.headers.get("user-agent"));
  const device = [os === "Mac OS X" ? "MacOS" : os, browser].filter(Boolean).join(", ");
  const when = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  }).format(now);
  return { ip, place, device, when: `${when} (KST)` };
}

function cause(reasons: readonly string[], blocked: boolean): { short: string; long: string; subject: string; verb: string } {
  const verb = blocked ? "차단" : "감지";
  if (reasons.includes("bot_detected") || reasons.includes("tampering_detected")) {
    return { short: "봇 의심", long: "봇 또는 변조된 브라우저로 의심됨", subject: `봇으로 의심되는 로그인 시도를 ${verb}했습니다`, verb };
  }
  return { short: "위험 네트워크", long: "위험한 네트워크(Tor 또는 차단된 IP)에서 접속", subject: `위험한 네트워크의 로그인 시도를 ${verb}했습니다`, verb };
}

export function alertMessages(env: Env, account: string, reasons: readonly string[], ctx: AlertContext, blocked = true) {
  const base = new URL(env.AUTH_BASE_URL).origin;
  const host = new URL(base).host;
  const why = cause(reasons, blocked);
  const email = [
    blocked ? `${account} 계정으로 로그인하려는 시도를 차단했습니다.` : `${account} 계정으로 위험 신호가 있는 기기에서 로그인했습니다. 로그인은 막지 않았습니다.`,
    "",
    `시각   ${ctx.when}`,
    `IP     ${ctx.ip}`,
    `위치   ${ctx.place}`,
    `기기   ${ctx.device}`,
    `사유   ${why.long}`,
    "",
    blocked ? "비밀번호는 맞았지만 기기 검사에서 차단했고, 계정에는 접속되지 않았습니다." : "비밀번호는 맞았고 기기 검사에서 위험 신호가 있었지만 로그인은 허용했습니다.",
    "",
    "본인이 시도한 것이 맞다면",
    " - 브라우저 확장 프로그램을 끄거나 다른 브라우저로 다시 시도하세요.",
    " - 계속 막히면 관리자에게 문의하세요.",
    "",
    "본인이 아니라면 비밀번호가 노출됐을 수 있습니다.",
    ` - 비밀번호 변경과 2차 인증 확인: ${base}/security`,
    ` - 최근 활동: ${base}/activity`,
    "",
    "이 메일은 발신 전용입니다.",
  ].join("\n");
  const sms = [`[Solix] ${why.short} 로그인 ${blocked ? "차단" : "감지"}`, ctx.ip, ctx.place, ctx.device, `본인이 아니면 비밀번호 변경: ${host}/security`].join("\n");
  return { subject: `[Solix] ${why.subject}`, email, sms, notice: `${ctx.place} · ${ctx.ip} · ${ctx.device}에서 ${why.short} 로그인을 ${why.verb}했습니다.` };
}

/**
 * Tell the account owner that a sign-in was blocked after the password proof
 * succeeded. Best effort: it never throws and never changes the sign-in result.
 * One alert per hour and five per day per account, so a loop cannot flood a phone.
 */
export async function alertRiskyLogin(env: Env, input: { userId: string; request: Request; reasons: readonly string[]; blocked?: boolean }): Promise<void> {
  try {
    if (!isBlockingRisk(input.reasons)) return;
    const now = new Date();
    const recent = await env.DB.prepare(
      "SELECT created_at FROM user_notifications WHERE user_id = ? AND kind = ? AND created_at >= ? ORDER BY created_at DESC",
    ).bind(input.userId, NOTICE_KIND, new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString()).all<{ created_at: string }>();
    const rows = recent.results ?? [];
    if (rows.length >= ALERTS_PER_DAY) return;
    if (rows[0] && Date.parse(rows[0].created_at) > now.getTime() - ALERT_WINDOW_MS) return;

    const user = await env.DB.prepare(
      'SELECT email, "phoneNumber" AS phone, "phoneNumberVerified" AS phoneVerified FROM "user" WHERE id = ?',
    ).bind(input.userId).first<{ email: string; phone: string | null; phoneVerified: number | boolean | null }>();
    if (!user) return;

    const ctx = describeAttempt(input.request, now);
    const text = alertMessages(env, user.email, input.reasons, ctx, input.blocked ?? true);
    await notifyUser(env, input.userId, { kind: NOTICE_KIND, title: text.subject.replace("[Solix] ", ""), body: text.notice, link: "/activity" });

    await sendTransactionEmail(env, { to: user.email, subject: text.subject, text: text.email })
      .catch((error) => console.error("risky login email failed", error instanceof Error ? error.message : String(error)));
    if (user.phone && (user.phoneVerified === true || user.phoneVerified === 1) && smsAvailable(env)) {
      await sendSms(env, { to: user.phone, text: text.sms }).catch(() => undefined);
    }
  } catch (error) {
    console.error("risky login alert failed", error instanceof Error ? error.message : String(error));
  }
}
