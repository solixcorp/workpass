import { afterEach, describe, expect, mock, test } from "bun:test";
import type { Env } from "../../src/env";
import { sendSmtpMail, type SmtpOptions } from "../../src/mail/providers/smtp/client";
import { deliverMessage } from "../../src/mail/send";

const MESSAGE = {
  from: "sender@example.test",
  to: "recipient@example.test",
  subject: "Activation",
  text: "Your OTP is 123456; https://auth.example.test/activate?token=secret",
};
const OPTIONS: SmtpOptions = {
  host: "smtp.example.test",
  port: 587,
  transport: "starttls",
  credentials: { username: "smtp-user", password: "smtp-password" },
  timeoutMs: 50,
};

// No network: the Workers socket module is replaced at its lazy import boundary.
let connectSocket: (address: unknown, options: unknown) => unknown;
mock.module("cloudflare:sockets", () => ({
  connect: (address: unknown, options: unknown) => connectSocket(address, options),
}));
afterEach(() => {
  mock.restore();
});

function peer(options: { capabilities?: string; handshake?: "reject" | "pending"; rejectStartTls?: boolean; throwStartTls?: boolean } = {}) {
  const writes: Array<{ tls: boolean; text: string }> = [];
  let upgraded = false;
  let handshakeComplete = false;
  let closed = false;
  let connectionOptions: unknown;
  const encoder = new TextEncoder();
  function socket(tls: boolean) {
    let replies: ReadableStreamDefaultController<Uint8Array>;
    const readable = new ReadableStream<Uint8Array>({
      start(controller) {
        replies = controller;
        if (!tls) controller.enqueue(encoder.encode("220 smtp.example.test ready\r\n"));
      },
    });
    const reply = (text: string) => replies.enqueue(encoder.encode(text));
    return {
      readable,
      writable: new WritableStream<Uint8Array>({
        write(bytes) {
          const text = new TextDecoder().decode(bytes);
          writes.push({ tls, text });
          if (tls && text !== "QUIT\r\n" && !handshakeComplete) {
            throw new Error("write before TLS handshake completed");
          }
          if (text.startsWith("EHLO ")) {
            reply(`250-smtp.example.test\r\n${tls ? "" : options.capabilities ?? "250-STARTTLS\r\n"}250 AUTH PLAIN LOGIN\r\n`);
          } else if (text === "STARTTLS\r\n") {
            reply(options.rejectStartTls ? "454 TLS unavailable\r\n" : "220 Ready for TLS\r\n");
          } else if (text === "DATA\r\n") {
            reply("354 Send message\r\n");
          } else if (text === "QUIT\r\n") {
            reply("221 Bye\r\n");
          } else {
            reply("250 OK\r\n");
          }
        },
      }),
      get opened(): Promise<void> {
        if (!tls) return Promise.resolve();
        if (options.handshake === "reject") return Promise.reject(new Error("TLS handshake failed"));
        if (options.handshake === "pending") return new Promise(() => {});
        return Promise.resolve().then(() => { handshakeComplete = true; });
      },
      async close() { closed = true; },
      startTls() {
        if (options.throwStartTls) throw new Error("TLS upgrade failed");
        upgraded = true;
        return socket(true);
      },
    };
  }
  connectSocket = (_address, options) => {
    connectionOptions = options;
    return socket(false);
  };
  return {
    writes,
    get upgraded() { return upgraded; },
    get closed() { return closed; },
    get connectionOptions() { return connectionOptions; },
  };
}

function expectNoSensitiveWrites(server: ReturnType<typeof peer>) {
  for (const { text } of server.writes) {
    expect(text).not.toMatch(/^(AUTH|MAIL FROM|RCPT TO|DATA)\b/);
    expect(text).not.toContain(OPTIONS.credentials!.username);
    expect(text).not.toContain(OPTIONS.credentials!.password);
    expect(text).not.toContain(btoa(`\0${OPTIONS.credentials!.username}\0${OPTIONS.credentials!.password}`));
    expect(text).not.toContain(MESSAGE.text);
  }
  expect(server.closed).toBe(true);
}

describe("SMTP STARTTLS requirement", () => {
  test("missing STARTTLS rejects before credentials or message bytes are sent", async () => {
    const server = peer({ capabilities: "" });
    await expect(sendSmtpMail(OPTIONS, MESSAGE)).rejects.toThrow("STARTTLS required but not offered by the server");
    expect(server.writes.map(({ text }) => text)).toEqual(["EHLO [127.0.0.1]\r\n", "QUIT\r\n"]);
    expect(server.upgraded).toBe(false);
    expectNoSensitiveWrites(server);
  });

  test("a STARTTLS substring in another extension is not an advertisement", async () => {
    const server = peer({ capabilities: "250-X-NOSTARTTLS\r\n" });
    await expect(sendSmtpMail(OPTIONS, MESSAGE)).rejects.toThrow("STARTTLS required but not offered");
    expectNoSensitiveWrites(server);
  });

  test("successful upgrade re-EHLOs and sends credentials and message only over TLS", async () => {
    const server = peer();
    await sendSmtpMail(OPTIONS, MESSAGE);
    expect(server.upgraded).toBe(true);
    expect(server.writes.filter(({ tls }) => !tls).map(({ text }) => text))
      .toEqual(["EHLO [127.0.0.1]\r\n", "STARTTLS\r\n"]);
    const tlsWrites = server.writes.filter(({ tls }) => tls).map(({ text }) => text);
    expect(tlsWrites[0]).toBe("EHLO [127.0.0.1]\r\n");
    expect(tlsWrites.some((text) => text.startsWith("AUTH PLAIN "))).toBe(true);
    expect(tlsWrites.some((text) => text.includes("Your OTP is 123456"))).toBe(true);
    expect(server.closed).toBe(true);
  });

  for (const failure of [
    { rejectStartTls: true, error: "STARTTLS failed" },
    { throwStartTls: true, error: "TLS upgrade failed" },
    { handshake: "reject" as const, error: "TLS handshake failed" },
    { handshake: "pending" as const, error: "SMTP timeout: STARTTLS handshake" },
  ]) {
    test(`failed upgrade aborts delivery: ${failure.error}`, async () => {
      const server = peer(failure);
      await expect(sendSmtpMail(OPTIONS, MESSAGE)).rejects.toThrow(failure.error);
      expectNoSensitiveWrites(server);
    });
  }

  test("explicit plaintext remains allowed without STARTTLS", async () => {
    const server = peer({ capabilities: "" });
    await sendSmtpMail({ ...OPTIONS, port: 25, transport: "off" }, MESSAGE);
    expect(server.connectionOptions).toEqual({ secureTransport: "off", allowHalfOpen: false });
    expect(server.upgraded).toBe(false);
    expect(server.writes.some(({ text }) => text.startsWith("AUTH PLAIN "))).toBe(true);
    expect(server.writes.some(({ text }) => text.includes("Your OTP is 123456"))).toBe(true);
  });

  test("implicit TLS still connects with TLS enabled and never requests STARTTLS", async () => {
    const server = peer({ capabilities: "" });
    await sendSmtpMail({ ...OPTIONS, port: 465, transport: "implicit_tls" }, MESSAGE);
    expect(server.connectionOptions).toEqual({ secureTransport: "on", allowHalfOpen: false });
    expect(server.upgraded).toBe(false);
    expect(server.writes.some(({ text }) => text.includes("Your OTP is 123456"))).toBe(true);
  });

  test("dispatch propagates missing STARTTLS as a delivery failure", async () => {
    const server = peer({ capabilities: "" });
    const env = {
      AUTH_BASE_URL: "https://auth.example.test",
      MAIL_PROVIDER: "smtp",
      MAIL_SMTP_HOST: OPTIONS.host,
      MAIL_SMTP_PORT: "587",
      MAIL_SMTP_USERNAME: OPTIONS.credentials!.username,
      MAIL_SMTP_PASSWORD: OPTIONS.credentials!.password,
    } as unknown as Env;
    await expect(deliverMessage(env, MESSAGE, { purpose: "OTP" }))
      .rejects.toThrow("STARTTLS required but not offered by the server");
    expectNoSensitiveWrites(server);
  });
});
