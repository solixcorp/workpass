/**
 * OTP email delivery for the two-factor OTP method. Pluggable by design:
 * - MFA_OTP_EMAIL_WEBHOOK_URL: dev/mock receiver that records the code (used by
 *   the headless MFA smoke).
 * - RESEND_API_KEY + MFA_OTP_EMAIL_FROM: production delivery through Resend.
 * With neither configured the delivery throws and the caller fails closed —
 * the second factor is never silently "sent" into nothing.
 */

import type { Env } from "../env";

export interface OtpDelivery {
  to: string;
  userId: string;
  otp: string;
}

export async function sendOtpEmail(env: Env, delivery: OtpDelivery): Promise<void> {
  if (env.MFA_OTP_EMAIL_WEBHOOK_URL) {
    const response = await fetch(env.MFA_OTP_EMAIL_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...delivery, sentAt: new Date().toISOString() }),
    });
    if (!response.ok) {
      throw new Error(`OTP webhook delivery failed with status ${response.status}`);
    }
    return;
  }
  if (env.RESEND_API_KEY && env.MFA_OTP_EMAIL_FROM) {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: env.MFA_OTP_EMAIL_FROM,
        to: [delivery.to],
        subject: "Your sign-in code",
        text: `Your verification code is ${delivery.otp}. It expires in a few minutes. If you did not request it, ignore this message.`,
      }),
    });
    if (!response.ok) {
      throw new Error(`OTP email delivery failed with status ${response.status}`);
    }
    return;
  }
  // Witnessed fail-closed: without a delivery channel, OTP must not appear usable.
  console.error("OTP email delivery is requested but no sender is configured");
  throw new Error("OTP delivery is not configured");
}
