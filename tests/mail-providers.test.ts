import { describe, expect, test } from "bun:test";
import type { Env } from "../src/env";
import {
  MAIL_PROVIDER_IDS,
  isMailProviderConfigured,
  isMailProviderEnabled,
  resolveMailProvider,
  selectedMailProviderId,
} from "../src/mail/provider";
import { deliverMessage, sendTransactionEmail, transactionEmailAvailable } from "../src/mail/send";
import { cloudflareProvider } from "../src/mail/providers/cloudflare";
import { mailerooProvider } from "../src/mail/providers/maileroo";
import { resendProvider } from "../src/mail/providers/resend";
import { sesProvider, signSesRequest } from "../src/mail/providers/ses";
import { buildMimeMessage, quotedPrintable } from "../src/mail/providers/smtp/mime";
import { resolveSmtpTransport, smtpPort } from "../src/mail/providers/smtp";
import { parseAuthMethods } from "../src/mail/providers/smtp/client";
import { sendOtpEmail } from "../src/mfa/otp-senders";

function env(overrides: Record<string, string>): Env {
  return { AUTH_BASE_URL: "https://auth.example.test", ...overrides } as unknown as Env;
}

const MESSAGE = { to: "recipient@example.test", subject: "Welcome", text: "Your code is 123456", from: "noreply@example.test" };

function stubFetch(handler: (url: string, init?: RequestInit) => Response): { calls: Array<{ url: string; init?: RequestInit; body: unknown }> } {
  const calls: Array<{ url: string; init?: RequestInit; body: unknown }> = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ url, init, body });
    return handler(url, init);
  }) as typeof fetch;
  (globalThis.fetch as { __restore?: () => void }).__restore = () => {
    globalThis.fetch = original;
  };
  return { calls };
}

function restoreFetch(): void {
  (globalThis.fetch as { __restore?: () => void }).__restore?.();
}

describe("mail provider selection", () => {
  test("the provider id catalog covers exactly the five shipped providers", () => {
    expect([...MAIL_PROVIDER_IDS]).toEqual(["smtp", "resend", "cloudflare", "maileroo", "ses"]);
  });

  test("an unknown MAIL_PROVIDER value fails loudly, not silently", () => {
    expect(() => selectedMailProviderId(env({ MAIL_PROVIDER: "sendgrid" }))).toThrow(/not supported/);
    expect(isMailProviderConfigured(env({ MAIL_PROVIDER: "sendgrid" }))).toBe(false);
  });

  test("a legacy deployment with only RESEND_API_KEY stays on Resend", () => {
    const sample = env({ RESEND_API_KEY: "legacy-key" });
    expect(selectedMailProviderId(sample)).toBe("resend");
    expect(isMailProviderEnabled(sample)).toBe(true);
    expect(transactionEmailAvailable(sample)).toBe(true);
  });

  test("a deployment with nothing configured is unavailable and fails closed", () => {
    const sample = env({});
    expect(selectedMailProviderId(sample)).toBeNull();
    expect(isMailProviderEnabled(sample)).toBe(false);
    expect(transactionEmailAvailable(sample)).toBe(false);
  });

  test("a selected provider with missing credentials is named in the delivery error", async () => {
    const sample = env({ MAIL_PROVIDER: "cloudflare" });
    expect(resolveMailProvider(sample)?.id).toBe("cloudflare");
    expect(isMailProviderEnabled(sample)).toBe(false);
    await expect(deliverMessage(sample, MESSAGE, { purpose: "Invitation" })).rejects.toThrow(/MAIL_CLOUDFLARE_ACCOUNT_ID/);
  });
});

describe("resend provider", () => {
  test("sends through the API with the MAIL_ prefix taking precedence over the legacy key", async () => {
    const sample = env({ RESEND_API_KEY: "legacy", MAIL_RESEND_API_KEY: "preferred" });
    const { calls } = stubFetch(() => new Response(JSON.stringify({ id: "m1" }), { status: 200 }));
    try {
      await resendProvider.send(sample, { ...MESSAGE, fromName: "Internal Auth" });
    } finally {
      restoreFetch();
    }
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.resend.com/emails");
    expect((calls[0]!.init!.headers as Record<string, string>).Authorization).toBe("Bearer preferred");
    const body = calls[0]!.body as Record<string, unknown>;
    expect(body.from).toBe("Internal Auth <noreply@example.test>");
    expect(body.to).toEqual(["recipient@example.test"]);
  });

  test("a failed API call throws instead of counting as sent", async () => {
    const { } = stubFetch(() => new Response("missing scope", { status: 401 }));
    try {
      await expect(resendProvider.send(env({ RESEND_API_KEY: "k" }), MESSAGE)).rejects.toThrow(/401/);
    } finally {
      restoreFetch();
    }
  });
});

describe("cloudflare email sending provider", () => {
  test("posts to the account REST endpoint with the named-address from object", async () => {
    const sample = env({ MAIL_CLOUDFLARE_ACCOUNT_ID: "acct-1", MAIL_CLOUDFLARE_API_TOKEN: "tok" });
    const { calls } = stubFetch(() => new Response(JSON.stringify({ success: true, result: { delivered: [MESSAGE.to] } }), { status: 200 }));
    try {
      await cloudflareProvider.send(sample, { ...MESSAGE, fromName: "Auth" });
    } finally {
      restoreFetch();
    }
    expect(calls[0]!.url).toBe("https://api.cloudflare.com/client/v4/accounts/acct-1/email/sending/send");
    expect((calls[0]!.init!.headers as Record<string, string>).Authorization).toBe("Bearer tok");
    const body = calls[0]!.body as Record<string, unknown>;
    expect(body.from).toEqual({ address: "noreply@example.test", name: "Auth" });
    expect(body.subject).toBe("Welcome");
  });

  test("a delivered-but-not-success envelope is a failed delivery", async () => {
    stubFetch(() => new Response(JSON.stringify({ success: false, errors: [{ code: 10203, message: "sending_disabled" }] }), { status: 200 }));
    try {
      await expect(cloudflareProvider.send(env({ MAIL_CLOUDFLARE_ACCOUNT_ID: "a", MAIL_CLOUDFLARE_API_TOKEN: "t" }), MESSAGE))
        .rejects.toThrow(/10203/);
    } finally {
      restoreFetch();
    }
  });
});

describe("maileroo provider", () => {
  test("sends the plain text body with bearer authentication", async () => {
    const { calls } = stubFetch(() => new Response(JSON.stringify({ success: true, data: { reference_id: "r1" } }), { status: 200 }));
    try {
      await mailerooProvider.send(env({ MAIL_MAILEROO_API_KEY: "mlr-key" }), MESSAGE);
    } finally {
      restoreFetch();
    }
    expect(calls[0]!.url).toBe("https://smtp.maileroo.com/api/v2/emails");
    expect((calls[0]!.init!.headers as Record<string, string>).Authorization).toBe("Bearer mlr-key");
    const body = calls[0]!.body as Record<string, unknown>;
    expect(body.from).toEqual({ address: "noreply@example.test" });
    expect(body.plain).toBe("Your code is 123456");
    expect(body.subject).toBe("Welcome");
  });

  test("a payload too large response is named for what it is", async () => {
    stubFetch(() => new Response("{}", { status: 413 }));
    try {
      await expect(mailerooProvider.send(env({ MAIL_MAILEROO_API_KEY: "k" }), MESSAGE))
        .rejects.toThrow(/payload exceeds the maximum size/);
    } finally {
      restoreFetch();
    }
  });
});

describe("amazon ses provider", () => {
  test("signs the v2 SendEmail request with SigV4 headers", async () => {
    const sample = env({ MAIL_SES_REGION: "us-east-1", MAIL_SES_ACCESS_KEY_ID: "AKIDEXAMPLE", MAIL_SES_SECRET_ACCESS_KEY: "secret-access-key" });
    const payload = JSON.stringify({ FromEmailAddress: "noreply@example.test", Destination: { ToAddresses: [MESSAGE.to] } });
    const signed = await signSesRequest(sample, payload, new Date("2026-11-10T08:30:45.000Z"));
    expect(signed.url).toBe("https://email.us-east-1.amazonaws.com/v2/email/outbound-emails");
    expect(signed.amzDate).toBe("20261110T083045Z");
    expect(signed.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20261110\/us-east-1\/ses\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
    // Independently recompute the signature chain to pin the canonical form.
    const payloadHash = signed.payloadHash;
    const canonicalHeaders = `content-type:application/json\nhost:email.us-east-1.amazonaws.com\nx-amz-content-sha256:${payloadHash}\nx-amz-date:20261110T083045Z\n`;
    const canonicalRequest = ["POST", "/v2/email/outbound-emails", "", canonicalHeaders, "content-type;host;x-amz-content-sha256;x-amz-date", payloadHash].join("\n");
    async function hmac(key: Uint8Array | ArrayBuffer, data: string): Promise<ArrayBuffer> {
      const imported = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      return crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(data));
    }
    async function sha256Hex(data: string): Promise<string> {
      return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data)))]
        .map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    const stringToSign = ["AWS4-HMAC-SHA256", "20261110T083045Z", "20261110/us-east-1/ses/aws4_request", await sha256Hex(canonicalRequest)].join("\n");
    let key: Uint8Array | ArrayBuffer = new TextEncoder().encode(`AWS4secret-access-key`);
    key = await hmac(key, "20261110");
    key = await hmac(key, "us-east-1");
    key = await hmac(key, "ses");
    key = await hmac(key, "aws4_request");
    const signature = [...new Uint8Array(await hmac(key, stringToSign))].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(signed.authorization.endsWith(`Signature=${signature}`)).toBe(true);
  });

  test("sends the Simple content shape over the wire", async () => {
    const sample = env({ MAIL_SES_REGION: "eu-central-1", MAIL_SES_ACCESS_KEY_ID: "k", MAIL_SES_SECRET_ACCESS_KEY: "s" });
    const { calls } = stubFetch(() => new Response(JSON.stringify({ MessageId: "m1" }), { status: 200 }));
    try {
      await sesProvider.send(sample, { ...MESSAGE, fromName: "Auth" });
    } finally {
      restoreFetch();
    }
    expect(calls[0]!.url).toBe("https://email.eu-central-1.amazonaws.com/v2/email/outbound-emails");
    const body = calls[0]!.body as Record<string, unknown>;
    expect(body.FromEmailAddress).toBe("Auth <noreply@example.test>");
    expect((body.Content as Record<string, Record<string, unknown>>).Simple!.Body).toBeDefined();
  });
});

describe("smtp provider", () => {
  test("transport defaults follow the port, with explicit overrides winning", () => {
    expect(resolveSmtpTransport(env({}))).toBe("implicit_tls");
    expect(resolveSmtpTransport(env({ MAIL_SMTP_PORT: "587" }))).toBe("starttls");
    expect(resolveSmtpTransport(env({ MAIL_SMTP_PORT: "25", MAIL_SMTP_SECURE: "false" }))).toBe("off");
    expect(resolveSmtpTransport(env({ MAIL_SMTP_PORT: "25", MAIL_SMTP_STARTTLS: "true" }))).toBe("starttls");
    expect(smtpPort(env({}))).toBe(465);
  });

  test("AUTH method extraction covers plain, login, and absent advertisement", () => {
    const ehlo = "250-smtp.example.test\r\n250-AUTH PLAIN LOGIN\r\n250 SMTPUTF8";
    expect(parseAuthMethods(ehlo)).toEqual(["PLAIN", "LOGIN"]);
    expect(parseAuthMethods("250-smtp.example.test\r\n250 STARTTLS")).toEqual([]);
    expect(parseAuthMethods("250-AUTH=LOGIN")).toEqual(["LOGIN"]);
  });
});

describe("smtp mime assembly", () => {
  test("quotes printable bodies, encodes header words, and dot-stuffs lines", () => {
    const message = {
      to: "a@example.test",
      from: "noreply@example.test",
      fromName: "Internal Auth",
      subject: "코드 123456",
      text: "line one\n.leading dot\nend=",
    };
    const payload = buildMimeMessage(message, { now: new Date("2026-11-10T08:30:45Z"), messageId: "<fixed@example.test>" });
    expect(payload).toStartWith("From: \"Internal Auth\" <noreply@example.test>\r\nTo: a@example.test\r\n");
    expect(payload).toContain("Subject: =?UTF-8?Q?=EC=BD=94=EB=93=9C_123456?=");
    expect(payload).toContain("Content-Transfer-Encoding: quoted-printable");
    // Dot-stuffing: the leading-dot body line doubles on the wire.
    expect(payload).toContain("\r\n..leading dot\r\n");
    // The trailing "=" is transparent-encoded.
    expect(payload).toContain("end=3D\r\n");
    expect(payload.endsWith("\r\n.\r\n")).toBe(true);
  });

  test("an HTML alternative is wrapped in a multipart body", () => {
    const payload = buildMimeMessage({ ...MESSAGE, html: "<b>hello</b>" }, { messageId: "<x@example.test>" });
    expect(payload).toContain("multipart/alternative");
    expect(payload).toContain("<b>hello</b>");
  });

  test("quoted printable preserves ascii and escapes breaks and equals", () => {
    expect(quotedPrintable("a=1\nb")).toBe("a=3D1\r\nb");
  });
});

describe("dispatch and fail-closed paths", () => {
  test("the invitation webhook override records the message instead of delivering", async () => {
    const sample = env({});
    const { calls } = stubFetch(() => new Response("", { status: 200 }));
    try {
      await deliverMessage(sample, MESSAGE, { purpose: "Invitation", webhookUrl: "http://127.0.0.1:9999/invitations" });
    } finally {
      restoreFetch();
    }
    const body = calls[0]!.body as Record<string, unknown>;
    expect(calls[0]!.url).toBe("http://127.0.0.1:9999/invitations");
    expect(body.to).toBe(MESSAGE.to);
    expect((body.sentAt as string).length).toBeGreaterThan(0);
  });

  test("an unconfigured deployment throws and never pretends the message was sent", async () => {
    await expect(deliverMessage(env({}), MESSAGE, { purpose: "Invitation" })).rejects.toThrow(/not configured/);
    await expect(deliverMessage(env({}), MESSAGE, { purpose: "OTP" })).rejects.toThrow(/not configured/);
  });

  test("a missing sender address fails closed even with provider credentials", async () => {
    await expect(deliverMessage(env({ RESEND_API_KEY: "k" }), { ...MESSAGE, from: "" }, { purpose: "Invitation" }))
      .rejects.toThrow(/sender address/);
  });

  test("the OTP webhook contract keeps recording the raw code for headless receivers", async () => {
    const { calls } = stubFetch(() => new Response("", { status: 200 }));
    try {
      await sendOtpEmail(env({ MFA_OTP_EMAIL_WEBHOOK_URL: "http://127.0.0.1:9999/otp" }), {
        to: "user@example.test",
        userId: "u1",
        otp: "246810",
      });
    } finally {
      restoreFetch();
    }
    const body = calls[0]!.body as Record<string, unknown>;
    expect(body.otp).toBe("246810");
    expect(body.userId).toBe("u1");
  });

  test("OTP email routes through the selected provider with MAIL_FROM when per-purpose is absent", async () => {
    const sample = env({ RESEND_API_KEY: "k", MAIL_FROM: "auth-noreply@example.test" });
    const { calls } = stubFetch(() => new Response(JSON.stringify({ id: "m" }), { status: 200 }));
    try {
      await sendOtpEmail(sample, { to: "user@example.test", userId: "u1", otp: "246810" });
    } finally {
      restoreFetch();
    }
    const body = calls[0]!.body as Record<string, unknown>;
    expect(calls[0]!.url).toBe("https://api.resend.com/emails");
    expect(body.from).toBe("auth-noreply@example.test");
    expect(body.text).toContain("246810");
  });

  test("transactional email prefers the purpose sender over the generic default", async () => {
    const sample = env({ MAIL_PROVIDER: "resend", MAIL_RESEND_API_KEY: "k", MAIL_FROM: "generic@example.test", INVITATION_EMAIL_FROM: "invites@example.test" });
    const { calls } = stubFetch(() => new Response(JSON.stringify({ id: "m" }), { status: 200 }));
    try {
      await sendTransactionEmail(sample, { to: "new-hire@example.test", subject: "s", text: "t" });
    } finally {
      restoreFetch();
    }
    const body = calls[0]!.body as Record<string, unknown>;
    expect(body.from).toBe("invites@example.test");
  });
});
