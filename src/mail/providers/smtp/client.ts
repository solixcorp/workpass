/**
 * SMTP transport over a Workers TCP socket. Adapted from the MIT-licensed
 * worker-mailer (https://github.com/zou-yu/worker-mailer, Copyright (c)
 * zou-yu) — reduced to one message per connection, implicit TLS (465) or
 * STARTTLS (587), AUTH PLAIN / AUTH LOGIN. CRAM-MD5 and DSN extensions are
 * dropped (CRAM-MD5 needs an MD5 HMAC, which WebCrypto does not provide);
 * the client negotiates only what the server advertises and fails loudly
 * when it cannot authenticate.
 *
 * The `cloudflare:sockets` module is imported lazily so the bun test suite
 * (no worker runtime) never touches it unless an SMTP message is actually
 * delivered; MIME building and transport resolution are covered directly.
 */

import type { MailMessage } from "../../provider";
import { buildMimeMessage } from "./mime";

export type SmtpTransport = "implicit_tls" | "starttls" | "off";

export interface SmtpCredentials {
  username: string;
  password: string;
}

export interface SmtpOptions {
  host: string;
  port: number;
  /** implicit TLS ("implicit_tls"), STARTTLS upgrade ("starttls"), or plaintext ("off"). */
  transport: SmtpTransport;
  credentials?: SmtpCredentials;
  /** EHLO/HELO client name (usually the deployment origin host). */
  ehloName?: string;
  timeoutMs?: number;
}

type SocketReader = ReadableStreamDefaultReader<Uint8Array>;
type SocketWriter = WritableStreamDefaultWriter<Uint8Array>;

interface SmtpSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<void>;
  close: () => Promise<void>;
  startTls: () => SmtpSocket;
}

/** AUTH methods advertised in an EHLO response. */
export function parseAuthMethods(ehloResponse: string): string[] {
  const methods: string[] = [];
  if (!/\bAUTH\b/i.test(ehloResponse)) return methods;
  if (/\bAUTH[^\n]*\bPLAIN\b/i.test(ehloResponse)) methods.push("PLAIN");
  if (/\bAUTH[^\n]*\bLOGIN\b/i.test(ehloResponse)) methods.push("LOGIN");
  return methods;
}

class SmtpSession {
  private reader: SocketReader;
  private writer: SocketWriter;
  private socket: SmtpSocket;
  private readonly decoder = new TextDecoder();
  private readonly encoder = new TextEncoder();
  private readonly timeoutMs: number;
  /** Does this connection still require STARTTLS? Cleared only after TLS opens. */
  private wantsStartTls: boolean;

  constructor(socket: SmtpSocket, private readonly ehloName: string, wantsStartTls: boolean, timeoutMs: number) {
    this.socket = socket;
    this.reader = socket.readable.getReader() as SocketReader;
    this.writer = socket.writable.getWriter() as SocketWriter;
    this.timeoutMs = timeoutMs;
    this.wantsStartTls = wantsStartTls;
  }

  /** Race an operation against the response timeout, naming the phase for ops. */
  private withTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`SMTP timeout: ${label}`)), this.timeoutMs);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer)) as Promise<T>;
  }

  private async readReply(): Promise<string> {
    let response = "";
    while (true) {
      const { value, done } = await this.reader.read();
      if (done) throw new Error("SMTP connection closed by server");
      if (!value) continue;
      response += this.decoder.decode(value, { stream: true });
      if (!response.endsWith("\n")) continue;
      // Multi-line replies end at the first line with code + space.
      const lines = response.split(/\r?\n/);
      const lastLine = lines[lines.length - 2];
      if (lastLine !== undefined && /^\d+-/.test(lastLine)) continue;
      return response;
    }
  }

  private async writeLine(line: string): Promise<void> {
    await this.writer.write(this.encoder.encode(`${line}\r\n`));
  }

  private assertReply(response: string, code: "2" | "3", label: string): void {
    if (!response.startsWith(code)) {
      throw new Error(`SMTP ${label} failed: ${response.trim()}`);
    }
  }

  private async command(line: string, code: "2" | "3", label: string): Promise<string> {
    await this.writeLine(line);
    const response = await this.withTimeout(this.readReply(), label);
    this.assertReply(response, code, label);
    return response;
  }

  private async ehlo(): Promise<string> {
    const response = await this.command(`EHLO ${this.ehloName}`, "2", "EHLO");
    return response;
  }

  /** Fail closed when STARTTLS is required; re-EHLO after TLS opens per RFC 3207. */
  private async maybeStartTls(ehloResponse: string): Promise<string> {
    if (!this.wantsStartTls) return ehloResponse;
    if (!/^250[ -]STARTTLS(?:[ \t]|\r?$)/im.test(ehloResponse)) {
      throw new Error("SMTP STARTTLS required but not offered by the server");
    }
    await this.command("STARTTLS", "2", "STARTTLS");
    this.reader.releaseLock();
    this.writer.releaseLock();
    this.socket = this.socket.startTls();
    this.reader = this.socket.readable.getReader() as SocketReader;
    this.writer = this.socket.writable.getWriter() as SocketWriter;
    await this.withTimeout(this.socket.opened, "STARTTLS handshake");
    this.wantsStartTls = false;
    return this.ehlo();
  }

  private authenticate(ehloResponse: string, credentials?: SmtpCredentials): Promise<void> {
    const supported = parseAuthMethods(ehloResponse);
    if (!supported.length && credentials) return Promise.resolve();
    if (!credentials?.username || !credentials.password) {
      if (supported.length) {
        throw new Error("SMTP server requires authentication but no credentials are configured");
      }
      return Promise.resolve();
    }
    if (supported.includes("PLAIN")) {
      const token = btoa(`\u0000${credentials.username}\u0000${credentials.password}`);
      return this.command(`AUTH PLAIN ${token}`, "2", "AUTH PLAIN").then(() => undefined);
    }
    if (supported.includes("LOGIN")) {
      return (async () => {
        await this.command("AUTH LOGIN", "3", "AUTH LOGIN");
        await this.command(btoa(credentials.username), "3", "AUTH LOGIN username");
        await this.command(btoa(credentials.password), "2", "AUTH LOGIN password");
      })();
    }
    throw new Error(
      `SMTP server offers no supported AUTH method (advertised: ${supported.join(", ") || "none"})`,
    );
  }

  async deliver(message: MailMessage, credentials?: SmtpCredentials): Promise<void> {
    await this.withTimeout(this.socket.opened, "socket connect");
    const greeting = await this.withTimeout(this.readReply(), "server greeting");
    this.assertReply(greeting, "2", "connect");
    const capabilities = await this.maybeStartTls(await this.ehlo());
    await this.authenticate(capabilities, credentials);

    await this.command(`MAIL FROM:<${message.from}>`, "2", "MAIL FROM");
    await this.command(`RCPT TO:<${message.to}>`, "2", "RCPT TO");
    await this.command("DATA", "3", "DATA");
    // The MIME payload arrives with its own terminator; send it raw.
    await this.writer.write(this.encoder.encode(buildMimeMessage(message)));
    const accepted = await this.withTimeout(this.readReply(), "message body");
    this.assertReply(accepted, "2", "message body");
  }

  async close(): Promise<void> {
    try {
      await this.writeLine("QUIT");
      await this.withTimeout(this.readReply().catch(() => ""), "QUIT");
    } catch {
      // The server may close first; delivery already succeeded.
    }
    try {
      await this.socket.close();
    } catch {
      // Best-effort teardown.
    }
  }
}

/** Open a connection, deliver one message, and close the session. */
export async function sendSmtpMail(options: SmtpOptions, message: MailMessage): Promise<void> {
  const { connect } = await import("cloudflare:sockets");
  const socket = connect(
    { hostname: options.host, port: options.port },
    {
      secureTransport:
        options.transport === "implicit_tls" ? "on" : options.transport === "starttls" ? "starttls" : "off",
      allowHalfOpen: false,
    },
  ) as unknown as SmtpSocket;
  const session = new SmtpSession(socket, options.ehloName ?? "[127.0.0.1]", options.transport === "starttls", options.timeoutMs ?? 30_000);
  try {
    await session.deliver(message, options.credentials);
  } finally {
    await session.close();
  }
}
