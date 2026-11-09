/**
 * Operator tooling: perform a full signed SAML SSO round trip against a
 * running local workerd instance without a real service provider. The script
 * impersonates an SP: it generates the SP key and certificate, registers and
 * enables the SP through the administration API, signs an HTTP-Redirect
 * AuthnRequest, drives GET /saml/sso with an authenticated session, and then
 * verifies the returned POST-binding response exactly like a service provider
 * would, trusting only the published metadata.
 *
 *   bun run scripts/saml-sso-smoke.ts --migrate-token <t> --admin-token <t>
 *
 * Disposable local database and throwaway inline credentials only.
 */

import { toBase64Url, fromBase64Url } from "../tests/saml-x509";
import { buildTbsCertificateDer, finalizeCertificateDer } from "../tests/saml-x509";
import { importSamlServiceProviderTrustedKey } from "../src/saml/certificates";

interface Options {
  base: string;
  username: string;
  password: string;
  email: string;
  name: string;
  adminToken: string | null;
  migrateToken: string | null;
}

const rawArgs = Bun.argv.slice(2);
function readOption(key: string): string | null {
  const index = rawArgs.indexOf(`--${key}`);
  return index >= 0 && index + 1 < rawArgs.length ? rawArgs[index + 1]! : null;
}

const options: Options = {
  base: readOption("base") ?? "http://127.0.0.1:8787",
  username: readOption("username") ?? "benchadmin",
  password: readOption("password") ?? "BenchOnly-7d9Kpw9zL2",
  email: readOption("email") ?? "bench-admin@example.com",
  name: readOption("name") ?? "Bench Admin",
  adminToken: readOption("admin-token"),
  migrateToken: readOption("migrate-token"),
};
const base = new URL(options.base).origin;
const SSO_PATH = "/saml/sso";

const jar = new Map<string, string>();
function absorb(response: Response): void {
  for (const header of response.headers.getSetCookie()) {
    const pair = header.split(";")[0]!;
    const separator = pair.indexOf("=");
    if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}
function cookieHeader(): string {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}
async function call(path: string, init?: { method?: "GET" | "POST" | "DELETE"; body?: unknown; origin?: boolean }): Promise<Response> {
  const headers: Record<string, string> = {};
  if (cookieHeader()) headers.Cookie = cookieHeader();
  if (init?.origin) headers.Origin = base;
  if (init?.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${base}${path}`, {
    method: init?.method ?? "GET",
    headers,
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });
  absorb(response);
  return response;
}

function expect(step: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`PASS ${step}`);
    return;
  }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 400));
  process.exit(1);
}

function standardBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function randomId(prefix: string, length = 6): string {
  const raw = new Uint8Array(length);
  crypto.getRandomValues(raw);
  return `${prefix}-${toBase64Url(raw).toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 8)}`;
}

// --- stages ----------------------------------------------------------------
async function runStage(name: string, work: () => Promise<number>): Promise<number> {
  const started = performance.now();
  const status = await work();
  console.log(`PASS ${name} (${status}, ${Math.round(performance.now() - started)} ms)`);
  return status;
}

if (options.migrateToken) {
  const migrate = await fetch(`${base}/_internal/migrate`, { method: "POST", headers: { Authorization: `Bearer ${options.migrateToken}` } });
  expect("migration", migrate.status === 200, await migrate.clone().text());
}
if (options.adminToken) {
  const bootstrap = await fetch(`${base}/api/admin/bootstrap`, {
    method: "POST",
    headers: { Authorization: `Bearer ${options.adminToken}`, "Content-Type": "application/json", "Origin": base },
    body: JSON.stringify({ email: options.email, name: options.name, username: options.username, password: options.password }),
  });
  expect("bootstrap", [201, 409].includes(bootstrap.status), await bootstrap.clone().text());
}

const signIn = await call("/api/auth/sign-in/username", { method: "POST", origin: true, body: { username: options.username, password: options.password } });
expect("admin sign-in", signIn.status === 200, await signIn.clone().text());

// The synthetic SP identity and its certificate.
const spKeyPair = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
  true,
  ["sign", "verify"],
);
const exportJwk = await crypto.subtle.exportKey("jwk", spKeyPair.publicKey!);
const spModulus = fromBase64Url(exportJwk.n!);
const spExponent = fromBase64Url(exportJwk.e!);
const tbs = buildTbsCertificateDer({
  modulus: spModulus,
  exponent: spExponent,
  commonName: "saml-sso-smoke-sp",
  notBeforeUtc: new Date().toISOString().slice(2, 10).replace(/-/g, "") + "000000Z",
  notAfterUtc: new Date(Date.now() + 14 * 24 * 60 * 60_000).toISOString().slice(2, 10).replace(/-/g, "") + "235959Z",
  serial: Array.from(crypto.getRandomValues(new Uint8Array(8)), (byte) => byte & 0x7f),
});
const spSignature = new Uint8Array(
  await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, spKeyPair.privateKey!, new TextEncoder().encode(String.fromCharCode(...tbs))),
);
const spCertificatePem = importPemFromDer(finalizeCertificateDer(tbs, Array.from(spSignature)));
function importPemFromDer(der: number[]): string {
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  return `-----BEGIN CERTIFICATE-----\n${(btoa(binary).match(/.{1,64}/g) ?? []).join("\n")}\n-----END CERTIFICATE-----`;
}

const spEntityId = `https://${randomId("sp")}.test/metadata`;
const spAcsUrl = `https://${spEntityId.replace(/^https:\/\//, "").split("/")[0]}/acs`;

// Register and enable the SP through the administration API.
const register = await call("/api/admin/saml-service-providers", {
  method: "POST",
  origin: true,
  body: { entityId: spEntityId, acsUrl: spAcsUrl, signingCertificate: spCertificatePem },
});
const registerBody = await register.json().catch(() => ({})) as { provider?: { id?: string } };
expect("sp registered", register.status === 201, { status: register.status, body: registerBody });
const providerId = registerBody.provider?.id ?? "";
expect("provider id", providerId.length > 0, registerBody);
const enable = await call(`/api/admin/saml-service-providers/${providerId}/enable`, { method: "POST", origin: true });
expect("sp enabled", enable.status === 200, await enable.clone().text());

// A service provider trust point built only from published metadata.
const metadata = await fetch(`${base}/saml/metadata`);
expect("metadata published", metadata.status === 200, metadata.status);
const metadataText = await metadata.text();
const idpCertificatePem = `-----BEGIN CERTIFICATE-----\n${(metadataText.split("<ds:X509Certificate>")[1]!.split("</ds:X509Certificate>")[0]!).trim()}\n-----END CERTIFICATE-----\n`;
const idpTrustedKey = await importSamlServiceProviderTrustedKey(idpCertificatePem);

async function buildSignedSsoUrl(xml: string, signKey: CryptoKey, relayState?: string): Promise<string> {
  const compressed = await new Response(
    new Blob([new TextEncoder().encode(xml)]).stream().pipeThrough(new CompressionStream("deflate-raw")),
  ).arrayBuffer();
  const encoded = encodeURIComponent(standardBase64(new Uint8Array(compressed)));
  const sigAlg = encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
  const relay = relayState ? `&RelayState=${encodeURIComponent(relayState)}` : "";
  const message = `SAMLRequest=${encoded}${relay}&SigAlg=${sigAlg}`;
  const signature = encodeURIComponent(standardBase64(new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signKey, new TextEncoder().encode(message)))));
  return `${base}${SSO_PATH}?SAMLRequest=${encoded}${relay}&SigAlg=${sigAlg}&Signature=${signature}`;
}

const requestId = `_${randomId("sso", 12).replace(/-/g, "")}`;
const ssoUrl = await buildSignedSsoUrl(
  '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
  'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
  `ID="${requestId}" Version="2.0" IssueInstant="${new Date().toISOString().replace(/\.\d+Z$/, "Z")}" ` +
  `Destination="${base}${SSO_PATH}" AssertionConsumerServiceURL="${spAcsUrl}">` +
  `<saml:Issuer>${spEntityId}</saml:Issuer>` +
  "</samlp:AuthnRequest>",
  spKeyPair.privateKey!,
);
const sso = await fetch(ssoUrl, { headers: { Cookie: cookieHeader() } });
const ssoPage = await sso.text();
expect("sso delivered a post-binding page", sso.status === 200 && ssoPage.includes(`action="${spAcsUrl}"`), sso.status + " " + ssoPage.slice(0, 120));

// SP-side response verification trusting only the published metadata.
const responseField = (ssoPage.split('name="SAMLResponse" value="')[1] ?? "").split('"')[0] ?? "";
expect("page carries SAMLResponse", responseField.length > 0, ssoPage.slice(0, 200));
const responseXml = atob(responseField.split("&")[0]!);
const signedInfo = responseXml.slice(
  responseXml.indexOf("<ds:SignedInfo"),
  responseXml.indexOf("</ds:SignedInfo>") + "</ds:SignedInfo>".length,
);
const signatureValue = responseXml.slice(
  responseXml.indexOf("<ds:SignatureValue>") + "<ds:SignatureValue>".length,
  responseXml.indexOf("</ds:SignatureValue>"),
);
const signatureBytes = Uint8Array.from(fromBase64Url(signatureValue));
const signatureValid = await crypto.subtle.verify(
  { name: "RSASSA-PKCS1-v1_5" },
  idpTrustedKey,
  signatureBytes,
  new TextEncoder().encode(signedInfo),
);
expect("response signature verifies with metadata key", signatureValid);
const assertionStart = responseXml.indexOf("<saml:Assertion");
const assertionEnd = responseXml.indexOf("</saml:Assertion>") + "</saml:Assertion>".length;
const assertionWithSignature = responseXml.slice(assertionStart, assertionEnd);
const signatureElement = responseXml.slice(
  responseXml.indexOf("<ds:Signature", assertionStart),
  responseXml.indexOf("</ds:Signature>") + "</ds:Signature>".length,
);
const coreAssertion = assertionWithSignature.replace(signatureElement, "");
const digestValue = responseXml.slice(
  responseXml.indexOf("<ds:DigestValue>") + "<ds:DigestValue>".length,
  responseXml.indexOf("</ds:DigestValue>"),
);
const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(coreAssertion)));
let digestBinary = "";
for (const byte of digestBytes) digestBinary += String.fromCharCode(byte);
expect("assertion digest verifies", btoa(digestBinary) === digestValue);
expect("response carries InResponseTo", responseXml.includes(`InResponseTo="${requestId}"`));
expect("response recipient is the registered ACS", responseXml.includes(`Recipient="${spAcsUrl}"`));
expect("response audience is the SP entity", responseXml.includes(`<saml:Audience>${spEntityId}</saml:Audience>`));
expect("nameid is the signed-in account email", responseXml.includes(`>${options.email}<`));

// RelayState passthrough.
const relay = "smoke-relay-1";
const relayedSigned = await buildSignedSsoUrl(
  '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
  `ID="_${randomId("r2", 8).replace(/-/g, "")}" Version="2.0" IssueInstant="${new Date().toISOString().replace(/\.\d+Z$/, "Z")}" ` +
  `Destination="${base}${SSO_PATH}" AssertionConsumerServiceURL="${spAcsUrl}">` +
  `<saml:Issuer>${spEntityId}</saml:Issuer></samlp:AuthnRequest>`,
  spKeyPair.privateKey!,
  relay,
);
const relayed = await fetch(relayedSigned, { headers: { Cookie: cookieHeader() } });
const relayedPage = await relayed.text();
expect("relay state reaches the POST page", relayed.status === 200 && relayedPage.includes(`RelayState" value="${relay}`));

// Replay of the same signed request is rejected by the claim.
const replay = await fetch(ssoUrl, { headers: { Cookie: cookieHeader() } });
expect("replayed signed request rejected", replay.status === 400, replay.status + " " + (await replay.clone().text()).slice(0, 120));

// Eight concurrent requests for the same signed request: the atomic one-time
// claim must yield exactly one issuance and seven rejections.
const racedId = `_${randomId("r8", 12).replace(/-/g, "")}`;
const racedUrl = await buildSignedSsoUrl(
  '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
  `ID="${racedId}" Version="2.0" IssueInstant="${new Date().toISOString().replace(/\.\d+Z$/, "Z")}" ` +
  `Destination="${base}${SSO_PATH}" AssertionConsumerServiceURL="${spAcsUrl}">` +
  `<saml:Issuer>${spEntityId}</saml:Issuer></samlp:AuthnRequest>`,
  spKeyPair.privateKey!,
);
const racedStatuses = (await Promise.all(
  Array.from({ length: 8 }, () => fetch(racedUrl, { headers: { Cookie: cookieHeader() } }).then((r) => r.status)),
)).sort();
const successes = racedStatuses.filter((status) => status === 200).length;
const rejections = racedStatuses.filter((status) => status === 400).length;
expect("race yields one issuance and seven rejections", successes === 1 && rejections === 7, racedStatuses);

// Tampered request bytes break the binding signature.
const tamperedUrl = ssoUrl.replace(encodeURIComponent(spAcsUrl), encodeURIComponent(spAcsUrl.replace("acs", "ac1")));
const tampered = await fetch(tamperedUrl, { headers: { Cookie: cookieHeader() } });
expect("tampered request rejected", tampered.status === 400, tampered.status + " " + (await tampered.clone().text()).slice(0, 120));

// A request from an issuer without an enabled registration is rejected.
const strangerId = `_${randomId("s3", 8).replace(/-/g, "")}`;
const strangerUrl = await buildSignedSsoUrl(
  '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
  `ID="${strangerId}" Version="2.0" IssueInstant="${new Date().toISOString().replace(/\.\d+Z$/, "Z")}" ` +
  `Destination="${base}${SSO_PATH}" AssertionConsumerServiceURL="${spAcsUrl}">` +
  `<saml:Issuer>https://unregistered.test/metadata</saml:Issuer></samlp:AuthnRequest>`,
  spKeyPair.privateKey!,
);
const stranger = await fetch(strangerUrl, { headers: { Cookie: cookieHeader() } });
expect("unregistered issuer rejected with 401", stranger.status === 401, stranger.status + " " + (await stranger.clone().text()).slice(0, 120));

// The issuance is audited with actor and provider target.
const auditList = await call("/api/admin/audit-events?limit=100");
const auditJson = await auditList.json().catch(() => null) as { events?: Array<{ event_type?: string; target_user_id?: string }> } | null;
const issued = auditJson?.events?.find((event) => event.event_type === "saml.assertion.issue");
expect("assertion issuance audited", issued !== undefined && issued.target_user_id === providerId, issued ?? "no event");

console.log(`saml sso smoke OK on ${base}: signed redirect round trip, metadata-trusted response verification, relay state, replay and tamper rejection.`);
