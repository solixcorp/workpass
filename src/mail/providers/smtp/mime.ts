/**
 * MIME message assembly for the SMTP transport. Adapted from the MIT-licensed
 * worker-mailer (https://github.com/zou-yu/worker-mailer, Copyright (c)
 * zou-yu) — trimmed to what this IdP sends: one recipient set, text (with
 * optional HTML alternative), no attachments, no DSN overrides. Quoted
 * printable body encoding, RFC 2047 header encoding, and dot-stuffing are
 * retained because OTP passcodes and invitation bodies carry arbitrary text.
 */

import type { MailMessage } from "../../provider";

const encoder = new TextEncoder();

export function quotedPrintable(text: string, lineLength = 76): string {
  const bytes = encoder.encode(text);
  let result = "";
  let currentLineLength = 0;
  let index = 0;

  while (index < bytes.length) {
    const byte = bytes[index]!;
    let encoded: string | undefined;

    if (byte === 0x0a) {
      result += "\r\n";
      currentLineLength = 0;
      index += 1;
      continue;
    }
    if (byte === 0x0d) {
      if (index + 1 < bytes.length && bytes[index + 1] === 0x0a) {
        result += "\r\n";
        currentLineLength = 0;
        index += 2;
        continue;
      }
      encoded = "=0D";
    }

    if (encoded === undefined) {
      const isWhitespace = byte === 0x20 || byte === 0x09;
      const nextIsLineBreak = index + 1 >= bytes.length || bytes[index + 1] === 0x0a || bytes[index + 1] === 0x0d;
      const needsEncoding =
        (byte < 32 && !isWhitespace) ||
        byte > 126 ||
        byte === 61 ||
        (isWhitespace && nextIsLineBreak);
      encoded = needsEncoding ? `=${byte.toString(16).toUpperCase().padStart(2, "0")}` : String.fromCharCode(byte);
    }

    if (currentLineLength + encoded.length > lineLength - 3) {
      result += "=\r\n";
      currentLineLength = 0;
    }
    result += encoded;
    currentLineLength += encoded.length;
    index += 1;
  }
  return result;
}

/** RFC 2047 Q-encoding for header words that contain non-ASCII bytes. */
export function encodeHeaderValue(text: string): string {
  if (!/[^\x00-\x7F]/.test(text)) return text;
  let encoded = "";
  for (const byte of encoder.encode(text)) {
    if (byte >= 33 && byte <= 126 && byte !== 63 && byte !== 61 && byte !== 95) {
      encoded += String.fromCharCode(byte);
    } else if (byte === 32) {
      encoded += "_";
    } else {
      encoded += `=${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return `=?UTF-8?Q?${encoded}?=`;
}

/** "Name <email>" with the display name either bare-ASCII or RFC 2047 encoded. */
export function addressWithDisplayName(displayName: string | undefined, email: string): string {
  if (!displayName) return email;
  return `"${encodeHeaderValue(displayName)}" <${email}>`;
}

function safeBoundary(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(28));
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}${hex}`.replace(/[<>@,;:\\/[\]?=" ]/g, "_");
}

/**
 * Assemble the full SMTP DATA payload for a message, ending with the
 * terminator line. `now` and `messageId` are injectable for deterministic
 * tests; production gets wall-clock values.
 */
export function buildMimeMessage(message: MailMessage, options?: { now?: Date; messageId?: string }): string {
  if (!message.text && !message.html) {
    throw new Error("SMTP message requires text or html content");
  }
  const now = options?.now ?? new Date();
  const messageId = options?.messageId ?? `<${crypto.randomUUID()}@${message.from.split("@").pop()}>`;

  const headers: string[] = [
    `From: ${addressWithDisplayName(message.fromName, message.from)}`,
    `To: ${message.to}`,
  ];
  if (message.replyTo) headers.push(`Reply-To: ${message.replyTo}`);
  headers.push(`Subject: ${encodeHeaderValue(message.subject)}`);
  headers.push(`Date: ${now.toUTCString()}`);
  headers.push(`Message-ID: ${messageId}`);
  headers.push("MIME-Version: 1.0");

  let body: string;
  if (message.html) {
    const boundary = safeBoundary("alt_");
    headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
    let assembled = "";
    if (message.text) {
      assembled += `--${boundary}\r\n`;
      assembled += 'Content-Type: text/plain; charset="UTF-8"\r\n';
      assembled += "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
      assembled += `${quotedPrintable(message.text)}\r\n\r\n`;
    }
    assembled += `--${boundary}\r\n`;
    assembled += 'Content-Type: text/html; charset="UTF-8"\r\n';
    assembled += "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    assembled += `${quotedPrintable(message.html)}\r\n\r\n`;
    assembled += `--${boundary}--\r\n`;
    body = assembled;
  } else {
    headers.push('Content-Type: text/plain; charset="UTF-8"');
    headers.push("Content-Transfer-Encoding: quoted-printable");
    body = `${quotedPrintable(message.text)}\r\n`;
  }

  const payload = `${headers.join("\r\n")}\r\n\r\n${body}`;
  // Dot-stuffing (RFC 5321 4.5.2): a leading "." on any line doubles.
  const stuffed = (payload.startsWith(".") ? `.${payload}` : payload).replace(/\r\n\./g, "\r\n..");
  return `${stuffed}\r\n.\r\n`;
}
