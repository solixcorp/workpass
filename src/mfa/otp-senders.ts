/**
 * OTP email delivery for the two-factor OTP method. Pluggable by design:
 * - MFA_OTP_EMAIL_WEBHOOK_URL: dev/mock receiver that records the code (used by
 *   the headless MFA smoke).
 * - The selected mail provider (MAIL_PROVIDER; legacy Resend-only deployments
 *   stay on Resend) delivers production messages; the sender address comes
 *   from MFA_OTP_EMAIL_FROM with the generic MAIL_FROM default.
 * With neither configured the delivery throws and the caller fails closed —
 * the second factor is never silently "sent" into nothing.
 */

import type { Env } from "../env";
import { deliverMessage } from "../mail/send";
import { sendSms, smsAvailable } from "../sms/provider";
import { organizationName } from "../settings/registry";

export interface OtpDelivery {
  to: string;
  userId: string;
  otp: string;
}

export async function sendOtpEmail(env: Env, delivery: OtpDelivery): Promise<void> {
  await deliverMessage(env, {
    to: delivery.to,
    subject: "Your sign-in code",
    text: `Your verification code is ${delivery.otp}. It expires in a few minutes. If you did not request it, ignore this message.`,
    from: env.MFA_OTP_EMAIL_FROM ?? env.MAIL_FROM ?? "",
  }, {
    purpose: "OTP",
    // Keep the pre-provider webhook contract: the receiver records the raw
    // code (and the user it belongs to) directly, not only the message text.
    webhookUrl: env.MFA_OTP_EMAIL_WEBHOOK_URL,
    webhookPayload: { to: delivery.to, userId: delivery.userId, otp: delivery.otp },
  });
}

/**
 * SMS delivery for the phone-number OTP, through the provider an administrator
 * chose (or a legacy webhook). Fail-closed when unconfigured.
 */
export async function sendSmsCode(env: Env, delivery: { to: string; code: string }): Promise<void> {
  await sendSms(env, { to: delivery.to, code: delivery.code, text: `[${organizationName(env)}] 인증 코드: ${delivery.code}` });
}

/**
 * Route the two-factor OTP: to the user's verified phone number by SMS when
 * one exists, otherwise to the account email.
 */
export async function sendOtpWithFallback(env: Env, delivery: { userId: string; email: string; otp: string }): Promise<void> {
  let phoneNumber: string | null = null;
  try {
    const row = await env.DB.prepare(
      'SELECT "phoneNumber" AS phoneNumber FROM "user" WHERE id = ? AND "phoneNumberVerified" = 1 AND "phoneNumber" IS NOT NULL',
    ).bind(delivery.userId).first<{ phoneNumber: string }>();
    phoneNumber = row?.phoneNumber ?? null;
  } catch {
    // Not migrated yet, or no verified number: fall back to email.
  }
  if (phoneNumber) {
    await sendSmsCode(env, { to: phoneNumber, code: delivery.otp });
    await (await import("./otp-channel")).rememberOtpChannel(env, delivery.userId, delivery.otp, "sms");
    return;
  }
  await sendOtpEmail(env, { to: delivery.email, userId: delivery.userId, otp: delivery.otp });
  await (await import("./otp-channel")).rememberOtpChannel(env, delivery.userId, delivery.otp, "email");
}

/** Is SMS delivery configured for this deployment? */
export function isSmsOtpAvailable(env: Env): boolean {
  return smsAvailable(env);
}
