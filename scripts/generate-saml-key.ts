/**
 * Operator tooling: generate the identity provider SAML signing key pair and a
 * self-signed X.509 certificate, then verify the produced material imports and
 * signs exactly the way the runtime expects. Run with Bun:
 *
 *   bun run scripts/generate-saml-key.ts [--cn <name>] [--days <n>] [--out <dir>]
 *
 * The output maps to the SAML_IDP_* environment variables. The private key
 * must never be committed: store it as a platform secret, and treat rotation,
 * revocation and audited replacement as deliberate operator work.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildTbsCertificateDer,
  finalizeCertificateDer,
  derToPem,
} from "../tests/saml-x509";
import {
  importSamlIdpPrivateKey,
  importSamlServiceProviderTrustedKey,
} from "../src/saml/certificates";

interface Options {
  commonName: string;
  days: number;
  outDir: string | null;
}

const args = Bun.argv.slice(2);
function readOption(name: string): string | number | null {
  const index = args.indexOf(`--${name}`);
  if (index < 0 || index + 1 >= args.length) return null;
  return args[index + 1]!;
}

const cnOption = readOption("cn");
const daysOption = readOption("days");
const outOption = readOption("out");
const options: Options = {
  commonName: typeof cnOption === "string" && cnOption.length > 0 && cnOption.length <= 128 ? cnOption : "internal-auth SAML IdP",
  days: typeof daysOption === "string" && /^\d{1,5}$/.test(daysOption) && Number(daysOption) > 0 ? Number(daysOption) : 365 * 3,
  outDir: typeof outOption === "string" && outOption.length > 0 ? outOption : null,
};

const MIN_KEY_BITS = 2048;
const MAX_KEY_BITS = 4096;
const bitsOption = readOption("bits");
const modulusLength = Number.isInteger(Number(bitsOption))
  ? Math.min(MAX_KEY_BITS, Math.max(MIN_KEY_BITS, Number(bitsOption)))
  : 2048;

console.log(`Generating a ${modulusLength}-bit RSA signing key for "${options.commonName}"...`);
const keyPair = await crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength,
    publicExponent: new Uint8Array([1, 0, 1]),
  },
  true,
  ["sign", "verify"],
);
if (!keyPair.privateKey || !keyPair.publicKey) throw new Error("Key generation returned no pair");

const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
const modulusBytes = base64UrlToBytes(jwk.n!);
const exponentBytes = base64UrlToBytes(jwk.e!);
const pkcs8Bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));

const now = new Date();
const notBefore = new Date(now.getTime() - 5 * 60_000);
const notAfter = new Date(now.getTime() + options.days * 24 * 60 * 60_000);
// A positive serial: the first byte stays below 0x80 for DER INTEGER encoding.
const serial = Array.from(crypto.getRandomValues(new Uint8Array(8)), (byte) => byte & 0x7f);
const tbsBytes = buildTbsCertificateDer({
  modulus: new Uint8Array(modulusBytes),
  exponent: new Uint8Array(exponentBytes),
  commonName: options.commonName,
  notBeforeUtc: toUtcTime(notBefore),
  notAfterUtc: toUtcTime(notAfter),
  serial,
});
const signature = new Uint8Array(
  await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keyPair.privateKey, new TextEncoder().encode(String.fromCharCode(...tbsBytes))),
);
const certificateDer = finalizeCertificateDer(tbsBytes, Array.from(signature));
const certificatePem = derToPem(certificateDer);
const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${(pemBytesBase64(pkcs8Bytes).match(/.{1,64}/g) ?? []).join("\n")}\n-----END PRIVATE KEY-----\n`;

// Self-check: the produced material must import and verify in the same
// code paths the runtime uses.
const trustedKey = await importSamlServiceProviderTrustedKey(certificatePem);
const probe = new TextEncoder().encode("internal-auth key material probe");
const probeSignature = new Uint8Array(
  await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keyPair.privateKey, probe),
);
const verified = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, trustedKey, probeSignature, probe);
if (!verified) throw new Error("Generated certificate does not verify a probe signature");
const importedPrivateKey = await importSamlIdpPrivateKey(privateKeyPem);
const probeAgain = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, importedPrivateKey, probe);
const verifiedAgain = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, trustedKey, new Uint8Array(probeAgain), probe);
if (!verifiedAgain) throw new Error("Imported private key does not match the certificate");

console.log("\nAdd these to your Worker secret/environment configuration:\n");
const entityOption = readOption("entity");
const entityId = typeof entityOption === "string" && entityOption.startsWith("https://") && entityOption.length <= 2048
  ? entityOption
  : "https://<your-auth-host>/saml/metadata";
console.log(`SAML_IDP_ENTITY_ID=${entityId}   # the public metadata URL of your deployment`);
console.log("\nSAML_IDP_SIGNING_CERTIFICATE:");
console.log(certificatePem.trim());
console.log("\nSAML_IDP_SIGNING_PRIVATE_KEY:");
console.log(privateKeyPem.trim());
console.log("\nThe key pair was self-checked: the certificate imports as a trusted verify key and both the exported and imported private keys sign correctly against it.");

if (options.outDir) {
  const directory = options.outDir;
  if (existsSync(join(directory, "saml-idp-private-key.pem"))) {
    throw new Error(`Refusing to overwrite an existing key in ${directory}`);
  }
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "saml-idp-private-key.pem"), privateKeyPem, { mode: 0o600 });
  writeFileSync(join(directory, "saml-idp-certificate.pem"), certificatePem, { mode: 0o644 });
  console.log(`\nWritten to ${directory} (set restrictive permissions; never commit the private key to this repository).`);
}

function base64UrlToBytes(value: string): number[] {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Array.from(atob(base64), (char) => char.charCodeAt(0) & 0xff);
}

function pemBytesBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function toUtcTime(date: Date): string {
  const iso = date.toISOString().replace(/\.\d{3}Z$/, "Z");
  return iso.slice(2, 20).replace(/[-:]/g, "");
}
