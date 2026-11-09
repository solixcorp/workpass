/**
 * HTTP-Redirect binding message decoding and strict AuthnRequest parsing.
 * Decoding and parsing never trust the content: everything is allowlisted and
 * bounded, and the extracted values are only treated as verified after the
 * caller confirms the binding signature of these exact query bytes.
 */

const MAX_ENCODED_LENGTH = 32_768;
const MAX_XML_LENGTH = 65_536;
const SAML_PROTOCOL_URN = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_URN = "urn:oasis:names:tc:SAML:2.0:assertion";
const POST_BINDING_URN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

const XML_ENTITY_ESCAPES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
};

const ID_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,255}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/;
const XML_DECLARATION_PATTERN = /^<\?xml[^?]{0,256}\?>\s*/;

export interface ParsedSamlAuthnRequest {
  /** MUST be passed to the one-time claim before an assertion is issued. */
  id: string;
  issuer: string;
  issueInstant: Date;
  destination: string | null;
  acsUrl: string | null;
  protocolBinding: string | null;
  forceAuthn: boolean;
  isPassive: boolean;
}

/** Every rejection is deliberately generic so senders learn nothing. */
class SamlRequestError extends Error {
  constructor() {
    super("Invalid SAML authentication request");
  }
}

/** Copy into a standalone ArrayBuffer so the value types as BlobPart. */
function toArrayBufferStrict(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

/** Inflate a base64 encoded SAML message with a hard output bound. */
export async function inflateSamlMessage(encoded: string): Promise<string> {
  if (encoded.length === 0 || encoded.length > MAX_ENCODED_LENGTH) throw new SamlRequestError();
  let binary: string;
  try {
    binary = atob(encoded);
  } catch {
    throw new SamlRequestError();
  }
  if (binary.length === 0 || binary.length > MAX_ENCODED_LENGTH) throw new SamlRequestError();
  const compressed = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  const xml = await inflateBounded(compressed);
  if (xml.length === 0 || xml.length > MAX_XML_LENGTH) throw new SamlRequestError();
  return xml;
}

async function inflateBounded(compressed: Uint8Array): Promise<string> {
  // The SAMP binding de facto standard is raw DEFLATE; some senders use zlib.
  const formats: CompressionFormat[] = ["deflate-raw", "deflate"];
  for (const format of formats) {
    try {
      return await inflateWithFormat(compressed, format);
    } catch {
      // Try the next framing; the final failure throws below.
    }
  }
  throw new SamlRequestError();
}

async function inflateWithFormat(compressed: Uint8Array, format: CompressionFormat): Promise<string> {
  let stream: ReadableStream<Uint8Array>;
  try {
    const body = new Response(new Blob([toArrayBufferStrict(compressed)])).body;
    if (!body) throw new SamlRequestError();
    stream = body.pipeThrough(new DecompressionStream(format));
  } catch {
    throw new SamlRequestError();
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    let read: ReadableStreamReadResult<Uint8Array>;
    try {
      read = await reader.read();
    } catch {
      await reader.cancel().catch(() => undefined);
      throw new SamlRequestError();
    }
    if (read.done) break;
    total += read.value.byteLength;
    if (total > MAX_XML_LENGTH) {
      await reader.cancel().catch(() => undefined);
      throw new SamlRequestError();
    }
    chunks.push(read.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(merged);
  } catch {
    throw new SamlRequestError();
  }
}

/** Unescape only the five predefined XML entities; everything else rejects. */
function unescapeXmlText(value: string): string {
  let result = "";
  let cursor = 0;
  while (cursor < value.length) {
    const ampersand = value.indexOf("&", cursor);
    if (ampersand < 0) {
      result += value.slice(cursor);
      break;
    }
    const semicolon = value.indexOf(";", ampersand);
    if (semicolon < 0 || semicolon > ampersand + 6) throw new SamlRequestError();
    const replacement = XML_ENTITY_ESCAPES[value.slice(ampersand, semicolon + 1)];
    if (replacement === undefined) throw new SamlRequestError();
    result += value.slice(cursor, ampersand) + replacement;
    cursor = semicolon + 1;
  }
  return result;
}

interface StartTag {
  name: string;
  attributes: Map<string, string>;
  selfClosing: boolean;
  /** Index of the first byte after the '>' of this start tag. */
  end: number;
}

function scanStartTag(xml: string, position: number): StartTag {
  if (xml[position] !== "<") throw new SamlRequestError();
  let cursor = position + 1;
  const nameStart = cursor;
  while (cursor < xml.length && /[A-Za-z0-9_.:-]/.test(xml[cursor]!)) cursor += 1;
  if (cursor === nameStart) throw new SamlRequestError();
  const name = xml.slice(nameStart, cursor);
  const attributes = new Map<string, string>();
  for (;;) {
    while (cursor < xml.length && /\s/.test(xml[cursor]!)) cursor += 1;
    if (cursor >= xml.length) throw new SamlRequestError();
    const char = xml[cursor]!;
    if (char === ">") return { name, attributes, selfClosing: false, end: cursor + 1 };
    if (char === "/") {
      if (xml[cursor + 1] !== ">") throw new SamlRequestError();
      return { name, attributes, selfClosing: true, end: cursor + 2 };
    }
    // Attribute name: allowlist validation is done by the caller.
    const nameStart = cursor;
    while (cursor < xml.length && /[A-Za-z0-9_:-]/.test(xml[cursor]!)) cursor += 1;
    const attributeName = xml.slice(nameStart, cursor);
    if (!attributeName) throw new SamlRequestError();
    while (cursor < xml.length && /\s/.test(xml[cursor]!)) cursor += 1;
    if (xml[cursor] !== "=") throw new SamlRequestError();
    cursor += 1;
    while (cursor < xml.length && /\s/.test(xml[cursor]!)) cursor += 1;
    const quote = xml[cursor];
    if (quote !== '"' && quote !== "'") throw new SamlRequestError();
    const valueEnd = xml.indexOf(quote, cursor + 1);
    if (valueEnd < 0) throw new SamlRequestError();
    const rawValue = xml.slice(cursor + 1, valueEnd);
    if (/[<>]/.test(rawValue)) throw new SamlRequestError();
    if (attributes.has(attributeName)) throw new SamlRequestError();
    attributes.set(attributeName, unescapeXmlText(rawValue));
    cursor = valueEnd + 1;
  }
}

function readElementText(xml: string, position: number, name: string): { value: string; next: number } {
  const open = scanStartTag(xml, position);
  if (open.name !== name || open.selfClosing) throw new SamlRequestError();
  const closeTag = `</${name}>`;
  const close = xml.indexOf(closeTag, open.end);
  if (close < 0 || close - open.end > 2048) throw new SamlRequestError();
  const rawValue = xml.slice(open.end, close);
  if (rawValue.includes("<")) throw new SamlRequestError();
  return { value: unescapeXmlText(rawValue), next: close + closeTag.length };
}

function parseTimestamp(value: string): Date {
  if (!TIMESTAMP_PATTERN.test(value)) throw new SamlRequestError();
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new SamlRequestError();
  return parsed;
}

function readBoolean(value: string | undefined): boolean {
  if (value === undefined || value === "false") return false;
  if (value === "true") return true;
  throw new SamlRequestError();
}

/**
 * Parse only the constrained AuthnRequest shape this IdP accepts. DOCTYPE,
 * comments, processing instructions, character references, unknown
 * attributes and any nested content are rejected.
 */
export function parseSamlAuthnRequest(input: string): ParsedSamlAuthnRequest {
  if (input.includes("<!")) throw new SamlRequestError();
  const xml = input.replace(XML_DECLARATION_PATTERN, "");
  if (xml.includes("<?")) throw new SamlRequestError();
  const root = scanStartTag(xml, 0);
  if (root.name !== "samlp:AuthnRequest" || root.selfClosing) throw new SamlRequestError();
  if (root.attributes.get("xmlns:samlp") !== SAML_PROTOCOL_URN) throw new SamlRequestError();
  if (root.attributes.get("xmlns:saml") !== SAML_ASSERTION_URN) throw new SamlRequestError();
  for (const name of root.attributes.keys()) {
    if (
      name !== "xmlns:samlp" && name !== "xmlns:saml" &&
      !["ID", "Version", "IssueInstant", "Destination", "AssertionConsumerServiceURL", "ProtocolBinding", "IsPassive", "ForceAuthn"].includes(name)
    ) throw new SamlRequestError();
  }
  const id = root.attributes.get("ID") ?? "";
  if (!ID_PATTERN.test(id) || root.attributes.get("Version") !== "2.0") throw new SamlRequestError();
  const issueInstant = parseTimestamp(root.attributes.get("IssueInstant") ?? "");
  const protocolBinding = root.attributes.get("ProtocolBinding") ?? null;
  if (protocolBinding !== null && protocolBinding !== POST_BINDING_URN) throw new SamlRequestError();

  const destination = root.attributes.get("Destination") ?? null;
  const acsUrl = root.attributes.get("AssertionConsumerServiceURL") ?? null;
  if (destination !== null && (destination.length > 2048 || /[\u0000-\u0020]/.test(destination))) {
    throw new SamlRequestError();
  }
  if (acsUrl !== null && (acsUrl.length > 2048 || /[\u0000-\u0020]/.test(acsUrl))) {
    throw new SamlRequestError();
  }

  let cursor = root.end;
  while (cursor < xml.length && /\s/.test(xml[cursor]!)) cursor += 1;
  const issuer = readElementText(xml, cursor, "saml:Issuer");
  if (issuer.value.length === 0 || issuer.value.length > 2048) throw new SamlRequestError();
  cursor = issuer.next;
  while (cursor < xml.length && /\s/.test(xml[cursor]!)) cursor += 1;

  const closing = `</samlp:AuthnRequest>`;
  if (xml.startsWith(closing, cursor)) {
    const remainder = xml.slice(cursor + closing.length);
    if (/\S/.test(remainder)) throw new SamlRequestError();
    return {
      id,
      issuer: issuer.value,
      issueInstant,
      destination,
      acsUrl,
      protocolBinding,
      forceAuthn: readBoolean(root.attributes.get("ForceAuthn")),
      isPassive: readBoolean(root.attributes.get("IsPassive")),
    };
  }
  // The only additional child accepted is a bare samlp:NameIDPolicy.
  const policy = scanStartTag(xml, cursor);
  if (policy.name !== "samlp:NameIDPolicy") throw new SamlRequestError();
  for (const name of policy.attributes.keys()) {
    if (!["AllowCreate", "Format", "SPNameQualifier"].includes(name)) throw new SamlRequestError();
  }
  const format = policy.attributes.get("Format");
  if (format && format !== "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" &&
      format !== "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified") throw new SamlRequestError();
  if (policy.attributes.has("SPNameQualifier")) throw new SamlRequestError();
  readBoolean(policy.attributes.get("AllowCreate"));
  cursor = policy.end;
  if (!policy.selfClosing) {
    if (!xml.startsWith("</samlp:NameIDPolicy>", cursor)) throw new SamlRequestError();
    cursor += "</samlp:NameIDPolicy>".length;
  }
  while (cursor < xml.length && /\s/.test(xml[cursor]!)) cursor += 1;
  if (!xml.startsWith(closing, cursor) || /\S/.test(xml.slice(cursor + closing.length))) {
    throw new SamlRequestError();
  }
  return {
    id,
    issuer: issuer.value,
    issueInstant,
    destination,
    acsUrl,
    protocolBinding,
    forceAuthn: readBoolean(root.attributes.get("ForceAuthn")),
    isPassive: readBoolean(root.attributes.get("IsPassive")),
  };
}

/** Escape for element text, matching exclusive C14N (& < > only). */
export function escapeSamlText(value: string): string {
  return value.replace(/[&<>]/g, (char) => {
    switch (char) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      default: return "&gt;";
    }
  });
}

/**
 * Escape for attribute values, matching exclusive C14N (&, < and " only).
 * Values containing tab, newline or carriage return are rejected by
 * registration validation instead of using control-character references.
 */
export function escapeSamlAttribute(value: string): string {
  return value.replace(/[&<"]/g, (char) => {
    switch (char) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      default: return "&quot;";
    }
  });
}

/** Escape for HTML attributes in the POST binding page (forms are unsigned). */
export function escapeSamlXml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&apos;";
    }
  });
}
