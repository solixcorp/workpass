/** Small helpers shared across HTTP mail providers. */

import type { MailMessage } from "../provider";

/**
 * Render "Name <address>" for APIs that take the sender as a single header
 * string (Resend, SES). Only printable-ASCII display names are inlined —
 * RFC 2047 encoding belongs to the SMTP provider's MIME composition.
 */
export function fromWithName(message: MailMessage): string {
  if (message.fromName && /^[\x20-\x7E]*$/.test(message.fromName)) {
    return `${message.fromName} <${message.from}>`;
  }
  return message.from;
}

/**
 * Include a bounded response body snippet in delivery errors. Providers use
 * this so a 4xx from the API names the actual problem (wrong sender domain,
 * bad key) instead of a bare status.
 */
export async function deliveryError(prefix: string, response: Response): Promise<Error> {
  let detail = "";
  try {
    const text = await response.text();
    detail = text.length > 300 ? `${text.slice(0, 300)}…` : text;
  } catch {
    // Body unreadable; the status alone is still actionable.
  }
  return new Error(detail ? `${prefix}: ${response.status} — ${detail}` : `${prefix}: ${response.status}`);
}
