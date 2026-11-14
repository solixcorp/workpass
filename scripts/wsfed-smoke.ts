/**
 * Operator tooling: drive the WS-Federation passive sign-in profile end to
 * end against a running local workerd instance, verifying the issued token
 * exactly like a legacy relying party would, trusting only published metadata.
 *
 *   bun run scripts/wsfed-smoke.ts [--migrate-token t] [--admin-token t]
 *
 * Disposable local database and throwaway inline credentials only.
 */

import { buildTbsCertificateDer, finalizeCertificateDer, fromBase64Url } from "../tests/saml/saml-x509";
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

const jar = new Map<string, string>();
function absorb(response: Response): void {
  for (const header of response.headers.getSetCookie()) {
    const pair = header.split(";")[0]!;
    const separator = pair.indexOf("=");
    if (separator > 0) jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}
function cookiePair(): string {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}
async function call(path: string, init?: { method?: "GET" | "POST" | "DELETE"; body?: unknown; origin?: boolean }): Promise<Response> {
  const headers: Record<string, string> = {};
  if (cookiePair()) headers.Cookie = cookiePair();
  if (init?.origin) headers.Origin = base;
  if (init?.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${base}${path}`, { method: init?.method ?? "GET", headers, body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
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
expect("sign-in", signIn.status === 200, signIn.status);

// Register and enable a legacy relying party.
const realm = `https://wsfed-sp-${crypto.randomUUID().slice(0, 8)}.test`;
const replyUrl = `${realm}/signin-callback`;
const register = await call("/api/admin/wsfed-relying-parties", { method: "POST", origin: true, body: { realm, replyUrl } });
const registerBody = await register.json().catch(() => ({})) as { party?: { id?: string } };
expect("relying party registered", register.status === 201, { status: register.status, body: registerBody });
const partyId = registerBody.party?.id ?? "";
const enable = await call(`/api/admin/wsfed-relying-parties/${partyId}/enable`, { method: "POST", origin: true });
expect("relying party enabled", enable.status === 200, enable.status);

// The relying party derives its trust point only from published metadata.
const metadataResponse = await fetch(`${base}/wsfed/metadata`);
const metadataXml = await metadataResponse.text();
expect("federation metadata published", metadataResponse.status === 200 && metadataXml.includes("md:KeyDescriptor"), metadataResponse.status);
const certificatePem = `-----BEGIN CERTIFICATE-----\n${(metadataXml.split("<ds:X509Certificate>")[1]!.split("</ds:X509Certificate>")[0]!).trim()}\n-----END CERTIFICATE-----\n`;
const idpTrustedKey = await importSamlServiceProviderTrustedKey(certificatePem);

// Passive sign-in with sessions.
const signinUrl = `${base}/wsfed/signin?wa=wsignin1.0&wtrealm=${encodeURIComponent(realm)}&wctx=${encodeURIComponent("smoke-ctx=1")}&wreply=${encodeURIComponent(replyUrl)}`;
const signin = await fetch(signinUrl, { headers: { Cookie: cookiePair() } });
const signinPage = await signin.text();
expect("sign-in delivers a post-binding page", signin.status === 200 && signinPage.includes(`action="${replyUrl}"`), signin.status + " " + signinPage.slice(0, 140));
const wresultField = (signinPage.split('name="wresult" value="')[1] ?? "").split('"')[0] ?? "";
expect("page carries wresult", wresultField.length > 0, signinPage.slice(0, 160));
const wctxEchoed = (signinPage.split('name="wctx" value="')[1] ?? "").split('"')[0] ?? "";
expect("wctx echoed", wctxEchoed === "smoke-ctx=1", wctxEchoed);

// Decode the result and verify like a legacy relying party.
const resultXml = decodeURIComponent(escape(atob(wresultField)));
expect("result is a WS-Trust response", resultXml.includes("RequestSecurityTokenResponse") && resultXml.includes("<saml:Assertion"));
const assertionStart = resultXml.indexOf("<saml:Assertion");
const assertionEnd = resultXml.indexOf("</saml:Assertion>") + "</saml:Assertion>".length;
const assertionWithSignature = resultXml.slice(assertionStart, assertionEnd);
const signatureElement = resultXml.slice(
  resultXml.indexOf("<ds:Signature", assertionStart),
  resultXml.indexOf("</ds:Signature>") + "</ds:Signature>".length,
);
const coreAssertion = assertionWithSignature.replace(signatureElement, "");
const signedInfo = resultXml.slice(
  resultXml.indexOf("<ds:SignedInfo"),
  resultXml.indexOf("</ds:SignedInfo>") + "</ds:SignedInfo>".length,
);
const signatureValue = resultXml.slice(
  resultXml.indexOf("<ds:SignatureValue>") + "<ds:SignatureValue>".length,
  resultXml.indexOf("</ds:SignatureValue>"),
);
const signatureValid = await crypto.subtle.verify(
  { name: "RSASSA-PKCS1-v1_5" },
  idpTrustedKey,
  fromBase64Url(signatureValue),
  new TextEncoder().encode(signedInfo),
);
expect("token signature verifies with the metadata key", signatureValid);
const digestValue = resultXml.slice(
  resultXml.indexOf("<ds:DigestValue>") + "<ds:DigestValue>".length,
  resultXml.indexOf("</ds:DigestValue>"),
);
const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(coreAssertion)));
let digestBinary = "";
for (const byte of digestBytes) digestBinary += String.fromCharCode(byte);
expect("assertion digest verifies", btoa(digestBinary) === digestValue);
expect("audience is the registered realm", resultXml.includes(`<saml:Audience>${realm}</saml:Audience>`));
expect("name identifier is the signed-in email", resultXml.includes(`>${options.email}<`));
const expiresMatch = /<wsu:Expires[^>]*>([^<]*)<\/wsu:Expires>/.exec(resultXml);
const createdMatch = /<wsu:Created[^>]*>([^<]*)<\/wsu:Created>/.exec(resultXml);
expect(
  "lifetime is bounded to five minutes",
  expiresMatch !== null && createdMatch !== null &&
  Date.parse(expiresMatch[1]!) - Date.parse(createdMatch[1]!) === 5 * 60_000 + 30_000,
  { created: createdMatch?.[1], expires: expiresMatch?.[1] },
);

// Negative paths: unknown realm, wrong reply, oversized context, signout.
const stranger = await fetch(`${base}/wsfed/signin?wa=wsignin1.0&wtrealm=${encodeURIComponent("https://unknown.test")}`, { headers: { Cookie: cookiePair() } });
expect("unknown realm rejected with 401", stranger.status === 401, stranger.status);
const wrongReply = await fetch(`${base}/wsfed/signin?wa=wsignin1.0&wtrealm=${encodeURIComponent(realm)}&wreply=${encodeURIComponent(`${realm}/other`)}`, { headers: { Cookie: cookiePair() } });
expect("reply mismatch rejected", wrongReply.status === 400, wrongReply.status);
const oversized = await fetch(`${base}/wsfed/signin?wa=wsignin1.0&wtrealm=${encodeURIComponent(realm)}&wctx=${encodeURIComponent("x".repeat(400))}`, { headers: { Cookie: cookiePair() } });
expect("oversized context rejected", oversized.status === 400, oversized.status);
const signout = await fetch(`${base}/wsfed/signin?wa=wsignout1.0`, { headers: { Cookie: cookiePair() } });
expect("federated signout page", signout.status === 200, signout.status);
const unidentified = await fetch(`${base}/wsfed/signin?wa=unknown-wa`, { headers: { Cookie: cookiePair() } });
expect("unrecognized wa rejected", unidentified.status === 400, unidentified.status);

// The issuance is audited.
const auditList = await call("/api/admin/audit-events?limit=100");
const auditJson = await auditList.json().catch(() => null) as { events?: Array<{ event_type?: string; target_user_id?: string }> } | null;
const issuedEvent = auditJson?.events?.find((event) => event.event_type === "wsfed.token.issue");
expect("token issuance audited", issuedEvent !== undefined && issuedEvent.target_user_id === partyId, issuedEvent ?? "no event");

console.log("wsfed smoke OK: passive sign-in round trip, metadata-trusted token verification, context echo, negative paths and audit.");
