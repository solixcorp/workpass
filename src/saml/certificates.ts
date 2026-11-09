/**
 * Certificate and key material parsing for SAML. Only bounded DER structure
 * walking is performed here; certificate chain, expiry and revocation are NOT
 * validated. Callers must present a certificate whose PEM was stored by an
 * authorized administrator of a registered service provider.
 */

const PEM_CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----";
const PEM_CERTIFICATE_FOOTER = "-----END CERTIFICATE-----";
const PEM_PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
const PEM_PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
const MAX_PEM_LENGTH = 16_384;
const MAX_CERTIFICATE_BYTES = 8_192;

/** AlgorithmIdentifier OID for rsaEncryption (1.2.840.113549.1.1.1). */
const RSA_ENCRYPTION_OID = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);

const MIN_MODULUS_BYTES = 256; // 2048-bit RSA minimum

interface DerNode {
  tag: number;
  contentStart: number;
  contentEnd: number;
}

function decodeBase64Strict(value: string, maxBytes: number): Uint8Array | null {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  let decoded: string;
  try {
    decoded = atob(value);
  } catch {
    return null;
  }
  if (decoded.length > maxBytes) return null;
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
}

function readDerNode(bytes: Uint8Array, pos: number): DerNode | null {
  if (pos + 2 > bytes.length) return null;
  const tag = bytes[pos]!;
  const lengthByte = bytes[pos + 1]!;
  let length: number;
  let contentStart: number;
  // RSA exponent 65537 is 3 bytes; reject anything longer or malformed.
  if (lengthByte < 0x80) {
    length = lengthByte;
    contentStart = pos + 2;
  } else {
    const count = lengthByte & 0x7f;
    if (count < 1 || count > 3 || pos + 2 + count > bytes.length) return null;
    length = 0;
    for (let index = 0; index < count; index += 1) {
      const digit = bytes[pos + 2 + index]!;
      // The first length digit must not be zero (non-minimal DER encoding).
      if (index === 0 && digit === 0) return null;
      length = length * 256 + digit;
    }
    contentStart = pos + 2 + count;
  }
  const contentEnd = contentStart + length;
  if (contentEnd > bytes.length) return null;
  return { tag, contentStart, contentEnd };
}

function collectDerChildren(bytes: Uint8Array, node: DerNode): DerNode[] | null {
  const children: DerNode[] = [];
  let position = node.contentStart;
  while (position < node.contentEnd) {
    const child = readDerNode(bytes, position);
    if (!child) return null;
    children.push(child);
    position = child.contentEnd;
    if (children.length > 32) return null;
  }
  return children;
}

function isOidEqual(content: Uint8Array, expected: Uint8Array): boolean {
  if (content.length !== expected.length) return false;
  for (let index = 0; index < expected.length; index += 1) {
    if (content[index] !== expected[index]) return false;
  }
  return true;
}

function readIntegerBytes(bytes: Uint8Array, node: DerNode): Uint8Array | null {
  const content = bytes.subarray(node.contentStart, node.contentEnd);
  if (content.length === 0) return null;
  // Leading zero byte encodes a positive INTEGER; exactly one is allowed.
  let start = 0;
  if (content[0] === 0) start = 1;
  if (start === content.length) return null;
  return content.subarray(start);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/** Copy into a standalone ArrayBuffer so the value types as BufferSource. */
function toArrayBufferStrict(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

/**
 * Extract the SubjectPublicKeyInfo bytes of an RSA subject key from a PEM
 * encoded X.509 certificate. Anything unexpected about the structure rejects.
 */
export function extractRsaSubjectPublicKeyInfo(certificatePem: string): Uint8Array {
  if (certificatePem.length > MAX_PEM_LENGTH) {
    throw new Error("SAML signing certificate is too large");
  }
  const header = certificatePem.indexOf(PEM_CERTIFICATE_HEADER);
  const footer = certificatePem.lastIndexOf(PEM_CERTIFICATE_FOOTER);
  if (header < 0 || footer < 0 || footer < header) {
    throw new Error("SAML signing certificate is not PEM encoded");
  }
  const body = certificatePem
    .slice(header + PEM_CERTIFICATE_HEADER.length, footer)
    .replace(/\s+/g, "");
  const certificateBytes = decodeBase64Strict(body, MAX_CERTIFICATE_BYTES);
  if (!certificateBytes) throw new Error("SAML signing certificate body is not base64");

  const certificate = readDerNode(certificateBytes, 0);
  if (!certificate || certificate.tag !== 0x30 || certificate.contentEnd !== certificateBytes.length) {
    throw new Error("SAML signing certificate is not a single DER sequence");
  }
  const outer = collectDerChildren(certificateBytes, certificate);
  const tbs = outer && outer.length >= 1 && outer[0]!.tag === 0x30 ? outer[0] : null;
  if (!tbs || (outer?.length ?? 0) !== 3 || outer![1]!.tag !== 0x30 || outer![2]!.tag !== 0x03) {
    throw new Error("SAML signing certificate structure is unexpected");
  }
  // Locate the SubjectPublicKeyInfo: a SEQUENCE whose AlgorithmIdentifier is
  // rsaEncryption and whose second child is the BIT STRING with the key.
  const tbsChildren = collectDerChildren(certificateBytes, tbs);
  if (!tbsChildren) throw new Error("SAML signing certificate body is malformed");
  for (const node of tbsChildren) {
    if (node.tag !== 0x30) continue;
    const inner = collectDerChildren(certificateBytes, node);
    // SPKI children: AlgorithmIdentifier (SEQUENCE wrapping the OID) and the
    // BIT STRING carrying the RSA key.
    if (!inner || inner.length !== 2 || inner[0].tag !== 0x30 || inner[1].tag !== 0x03) continue;
    const algChildren = collectDerChildren(certificateBytes, inner[0]);
    if (!algChildren || algChildren.length < 1 || algChildren[0].tag !== 0x06) continue;
    const oid = certificateBytes.subarray(algChildren[0].contentStart, algChildren[0].contentEnd);
    if (!isOidEqual(oid, RSA_ENCRYPTION_OID)) continue;
    if (
      inner[1].contentEnd - inner[1].contentStart < 1 ||
      certificateBytes[inner[1].contentStart] !== 0
    ) continue;
    return certificateBytes.subarray(inner[1].contentStart + 1, inner[1].contentEnd);
  }
  throw new Error("SAML signing certificate does not contain an RSA public key");
}

/** Import the trusted RSA public key of a registered SP certificate for verify use. */
export async function importSamlServiceProviderTrustedKey(certificatePem: string): Promise<CryptoKey> {
  // The extract step already returns the RSAPublicKey SEQUENCE (modulus, exponent).
  const keyBytes = extractRsaSubjectPublicKeyInfo(certificatePem);
  const rsaKey = readDerNode(keyBytes, 0);
  let modulus: Uint8Array | null = null;
  let exponent: Uint8Array | null = null;
  if (rsaKey && rsaKey.tag === 0x30 && rsaKey.contentEnd === keyBytes.length) {
    const keyParts = collectDerChildren(keyBytes, rsaKey);
    if (keyParts && keyParts.length === 2 && keyParts[0].tag === 0x02 && keyParts[1].tag === 0x02) {
      modulus = readIntegerBytes(keyBytes, keyParts[0]);
      exponent = readIntegerBytes(keyBytes, keyParts[1]);
    }
  }
  if (!modulus || !exponent || modulus.length < MIN_MODULUS_BYTES || exponent.length > 8) {
    throw new Error("SAML signing certificate does not contain an acceptable RSA public key");
  }
  const exponentValue = exponent.reduce((value, byte) => value * 256 + byte, 0);
  if (exponentValue < 3 || exponentValue % 2 === 0) {
    throw new Error("SAML signing certificate RSA exponent is not usable");
  }
  return crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: bytesToBase64Url(modulus), e: bytesToBase64Url(exponent) },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

/** DER base64 body of a PEM certificate for embedding in ds:X509Certificate. */
export function pemCertificateDerBase64(certificatePem: string): string {
  if (certificatePem.length > MAX_PEM_LENGTH) {
    throw new Error("SAML identity provider certificate is too large");
  }
  const header = certificatePem.indexOf(PEM_CERTIFICATE_HEADER);
  const footer = certificatePem.lastIndexOf(PEM_CERTIFICATE_FOOTER);
  if (header < 0 || footer < 0 || footer < header) {
    throw new Error("SAML identity provider certificate is not PEM encoded");
  }
  const body = certificatePem
    .slice(header + PEM_CERTIFICATE_HEADER.length, footer)
    .replace(/\s+/g, "");
  if (!decodeBase64Strict(body, MAX_CERTIFICATE_BYTES)) {
    throw new Error("SAML identity provider certificate body is not base64");
  }
  return body;
}

/**
 * Import the IdP signing private key from PKCS#8 PEM. The key never leaves
 * WebCrypto: extraction is disabled and only signing is allowed.
 */
export async function importSamlIdpPrivateKey(privateKeyPem: string): Promise<CryptoKey> {
  if (privateKeyPem.length > MAX_PEM_LENGTH) {
    throw new Error("SAML identity provider private key is too large");
  }
  const header = privateKeyPem.indexOf(PEM_PRIVATE_KEY_HEADER);
  const footer = privateKeyPem.lastIndexOf(PEM_PRIVATE_KEY_FOOTER);
  if (header < 0 || footer < 0 || footer < header) {
    throw new Error("SAML identity provider private key must be PKCS#8 PEM");
  }
  const body = privateKeyPem
    .slice(header + PEM_PRIVATE_KEY_HEADER.length, footer)
    .replace(/\s+/g, "");
  const der = decodeBase64Strict(body, MAX_CERTIFICATE_BYTES);
  if (!der) throw new Error("SAML identity provider private key body is not base64");
  const key = await crypto.subtle.importKey(
    "pkcs8",
    toArrayBufferStrict(der),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  if (key.type !== "private" || key.algorithm.name !== "RSASSA-PKCS1-v1_5") {
    throw new Error("SAML identity provider private key is not an RSA signing key");
  }
  // @ts-expect-error RsaHashedKeyAlgorithm always carries modulusLength for RSA.
  if (key.algorithm.modulusLength < MIN_MODULUS_BYTES * 8) {
    throw new Error("SAML identity provider signing key is too small");
  }
  return key;
}
