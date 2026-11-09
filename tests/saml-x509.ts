/**
 * Shared X.509 DER builder for test and tooling support: constructs minimal,
 * structurally valid certificates around a supplied RSA public key.
 */

export const RSA_ENCRYPTION_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
export const SHA256_RSA_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
export const COMMON_NAME_OID = [0x55, 0x04, 0x03];

export function tlv(tag: number, content: number[]): number[] {
  if (content.length < 0x80) return [tag, content.length, ...content];
  const lengthBytes: number[] = [];
  let length = content.length;
  while (length > 0) {
    lengthBytes.unshift(length & 0xff);
    length >>= 8;
  }
  return [tag, 0x80 + lengthBytes.length, ...lengthBytes, ...content];
}

export function oid(value: number[]): number[] {
  return tlv(0x06, value);
}

function commonName(cn: string = "sp"): number[] {
  const attributeType = tlv(0x06, COMMON_NAME_OID);
  const value = tlv(0x0c, Array.from(cn, (char) => char.charCodeAt(0)));
  const attribute = tlv(0x30, [...attributeType, ...value]);
  return tlv(0x31, attribute);
}

function sha256RsaAlgorithm(): number[] {
  return tlv(0x30, oid(SHA256_RSA_OID));
}

export function buildCertificateDer(modulus: Uint8Array, exponent: Uint8Array): number[] {
  const modulusBytes = Array.from(modulus, (byte) => byte & 0xff);
  const exponentBytes = Array.from(exponent, (byte) => byte & 0xff);
  const modulusInteger = modulusBytes[0]! >= 0x80
    ? tlv(0x02, [0, ...modulusBytes])
    : tlv(0x02, modulusBytes);
  const rsaPublicKey = tlv(0x30, [...modulusInteger, ...tlv(0x02, exponentBytes)]);
  const spki = tlv(0x30, [
    ...tlv(0x30, oid(RSA_ENCRYPTION_OID)),
    ...tlv(0x03, [0, ...rsaPublicKey]),
  ]);
  const validity = tlv(0x30, [
    ...tlv(0x17, utctime("250101000000Z")),
    ...tlv(0x17, utctime("350101000000Z")),
  ]);
  const tbs = tlv(0x30, [
    ...tlv(0xa0, tlv(0x02, [0x02])),
    ...tlv(0x02, [0x01]),
    ...sha256RsaAlgorithm(),
    ...commonName(),
    ...validity,
    ...commonName(),
    ...spki,
  ]);
  return tlv(0x30, [
    ...tbs,
    ...sha256RsaAlgorithm(),
    ...tlv(0x03, [0, 0, 0]),
  ]);
}

function utctime(value: string): number[] {
  return Array.from(value, (char) => char.charCodeAt(0));
}

/** DER of the TBSCertificate for a self-signed certificate around the key. */
export function buildTbsCertificateDer(options: {
  modulus: Uint8Array;
  exponent: Uint8Array;
  commonName: string;
  notBeforeUtc: string;
  notAfterUtc: string;
  serial: number[];
}): number[] {
  const modulusBytes = Array.from(options.modulus, (byte) => byte & 0xff);
  const exponentBytes = Array.from(options.exponent, (byte) => byte & 0xff);
  const modulusInteger = modulusBytes[0]! >= 0x80
    ? tlv(0x02, [0, ...modulusBytes])
    : tlv(0x02, modulusBytes);
  const rsaPublicKey = tlv(0x30, [...modulusInteger, ...tlv(0x02, exponentBytes)]);
  const spki = tlv(0x30, [
    ...tlv(0x30, oid(RSA_ENCRYPTION_OID)),
    ...tlv(0x03, [0, ...rsaPublicKey]),
  ]);
  const name = tlv(0x31, tlv(0x30, [
    ...tlv(0x06, COMMON_NAME_OID),
    ...tlv(0x0c, Array.from(options.commonName, (char) => char.charCodeAt(0))),
  ]));
  const validity = tlv(0x30, [
    ...tlv(0x17, utctime(options.notBeforeUtc)),
    ...tlv(0x17, utctime(options.notAfterUtc)),
  ]);
  const tbs = tlv(0x30, [
    ...tlv(0xa0, tlv(0x02, [0x02])),
    ...tlv(0x02, options.serial),
    ...sha256RsaAlgorithm(),
    ...name,
    ...validity,
    ...name,
    ...spki,
  ]);
  return tbs;
}

/** Certificate DER from TBSCertificate bytes and the caller's RSA signature. */
export function finalizeCertificateDer(tbs: number[], signature: number[]): number[] {
  return tlv(0x30, [
    ...tbs,
    ...sha256RsaAlgorithm(),
    ...tlv(0x03, [0, ...signature]),
  ]);
}

export function derToPem(der: number[]): string {
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  const lines = (btoa(binary).match(/.{1,64}/g) ?? []).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}
