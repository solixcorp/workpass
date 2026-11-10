/**
 * Runtime-independent verification tests for the SAML primitives, executed
 * with Bun test (allowed by the stack decision for WebCrypto-dependent code
 * that does not touch Workers-specific bindings). These tests simulate an SP
 * sending a signed HTTP-Redirect request and verify the whole chain the IdP
 * route runs, plus a full round trip of the signed response.
 */

import { describe, expect, test } from "bun:test";
import {
  importSamlIdpPrivateKey,
  importSamlServiceProviderTrustedKey,
} from "../../src/saml/certificates";
import {
  inflateSamlMessage,
  parseSamlAuthnRequest,
} from "../../src/saml/request-binding";
import { verifySamlRedirectSignature } from "../../src/saml/redirect-signature";
import { buildSignedSamlResponse, type IssuedSamlResponse } from "../../src/saml/assertion";
import { buildSamlIdpMetadata } from "../../src/saml/metadata";
import { buildSsoLoginPage } from "../../src/pages/sso-login";
import { buildCertificateDer, derToPem } from "../saml/saml-x509";

const SP_ENTITY_ID = "https://sp.example.com/metadata";
const IDP_ENTITY_ID = "https://idp.example.com/metadata";
const SSO_URL = "https://idp.example.com/saml/sso";
const ACS_URL = "https://sp.example.com/acs";

function deflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
  return collect(new Blob([bytes]).stream().pipeThrough(new CompressionStream("deflate-raw")));
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const read = await reader.read();
    if (read.done) break;
    total += read.value.byteLength;
    chunks.push(read.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function authnRequestXml(options: { issueInstant: string; id?: string }): string {
  return (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    `ID="${options.id ?? "_authn-1"}" Version="2.0" IssueInstant="${options.issueInstant}" ` +
    `Destination="${SSO_URL}" AssertionConsumerServiceURL="${ACS_URL}">` +
    `<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>` +
    "</samlp:AuthnRequest>"
  );
}

interface SpSigning {
  privateKey: CryptoKey;
  certificatePem: string;
}

async function certificatePemFor(keyPair: CryptoKeyPair): Promise<string> {
  // The test certificate embeds the real public key of the supplied pair.
  const exportJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const realModulus = Array.from(atob(exportJwk.n!.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0) & 0xff);
  const realExponent = Array.from(atob(exportJwk.e!), (char) => char.charCodeAt(0) & 0xff);
  return derToPem(buildCertificateDer(new Uint8Array(realModulus), new Uint8Array(realExponent)));
}

async function createSpSigning(): Promise<SpSigning> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  );
  return {
    privateKey: keyPair.privateKey,
    certificatePem: await certificatePemFor(keyPair),
  };
}

function buildSignedRedirectUrl(sp: SpSigning, options: {
  xml: string;
  relayState?: string;
  sigAlg?: string;
}): Promise<string> {
  return buildSignedRedirectSigned(sp, options).then(({ url }) => url);
}

async function buildSignedRedirectSigned(sp: SpSigning, options: {
  xml: string;
  relayState?: string;
  sigAlg?: string;
}): Promise<{ url: string; signed: string; signature: Uint8Array }> {
  const compressed = await deflateRaw(new TextEncoder().encode(options.xml));
  const encoded = encodeURIComponent(base64(compressed));
  const sigAlgRaw = encodeURIComponent(options.sigAlg ?? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
  const relay = options.relayState ? `&RelayState=${encodeURIComponent(options.relayState)}` : "";
  const signed = `SAMLRequest=${encoded}${relay}&SigAlg=${sigAlgRaw}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, sp.privateKey, new TextEncoder().encode(signed)),
  );
  const url = `${SSO_URL}?SAMLRequest=${encoded}${relay}&SigAlg=${sigAlgRaw}&Signature=${encodeURIComponent(base64(signature))}`;
  return { url, signed, signature };
}

const NOW = new Date("2026-11-09T12:00:00Z");

describe("SP certificate and redirect signature chain", () => {
  test("accepts a signed AuthnRequest from the trusted SP certificate", async () => {
    const sp = await createSpSigning();
    const url = await buildSignedRedirectUrl(sp, { xml: authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }) });
    const trustedKey = await importSamlServiceProviderTrustedKey(sp.certificatePem);
    expect(trustedKey.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
    const verified = await verifySamlRedirectSignature(url, trustedKey);
    expect(verified).not.toBeNull();
    expect(verified!.samlRequest).not.toBeNull();
    const xml = await inflateSamlMessage(verified!.samlRequest);
    const parsed = parseSamlAuthnRequest(xml);
    expect(parsed.id).toBe("_authn-1");
    expect(parsed.issuer).toBe(SP_ENTITY_ID);
    expect(parsed.destination).toBe(SSO_URL);
    expect(parsed.acsUrl).toBe(ACS_URL);
    expect(parsed.issueInstant.toISOString()).toBe("2026-11-09T11:59:00.000Z");
  });

  test("rejects a tampered signature", async () => {
    const sp = await createSpSigning();
    const other = await createSpSigning();
    const url = await buildSignedRedirectUrl(sp, { xml: authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }) });
    const trustedKey = await importSamlServiceProviderTrustedKey(other.certificatePem);
    const verified = await verifySamlRedirectSignature(url, trustedKey);
    expect(verified).toBeNull();
  });

  test("rejects duplicate SAMLRequest parameters", async () => {
    const sp = await createSpSigning();
    const { url } = await buildSignedRedirectSigned(sp, { xml: authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }) });
    const duplicate = url.replace("SigAlg=", `SAMLRequest=zzz&SigAlg=`);
    const trustedKey = await importSamlServiceProviderTrustedKey(sp.certificatePem);
    expect(await verifySamlRedirectSignature(duplicate, trustedKey)).toBeNull();
  });

  test("rejects an unexpected signature algorithm", async () => {
    const sp = await createSpSigning();
    const url = await buildSignedRedirectUrl(sp, {
      xml: authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }),
      sigAlg: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    });
    const trustedKey = await importSamlServiceProviderTrustedKey(sp.certificatePem);
    expect(await verifySamlRedirectSignature(url, trustedKey)).toBeNull();
  });

  test("rejects percent-encoded parameter names", async () => {
    const sp = await createSpSigning();
    const url = await buildSignedRedirectUrl(sp, { xml: authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }) });
    const encoded = url.replace("SAMLRequest=", "S%41MLRequest=");
    const trustedKey = await importSamlServiceProviderTrustedKey(sp.certificatePem);
    expect(await verifySamlRedirectSignature(encoded, trustedKey)).toBeNull();
  });
});

describe("AuthnRequest XML validation", () => {
  test("accepts zlib-framed deflate as well as raw deflate", async () => {
    const zlib = await collect(new Blob([new TextEncoder().encode(authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }))])
      .stream()
      .pipeThrough(new CompressionStream("deflate")));
    const xml = await inflateSamlMessage(base64(zlib));
    expect(parseSamlAuthnRequest(xml).issuer).toBe(SP_ENTITY_ID);
  });

  test("rejects unknown root attributes", async () => {
    const xml = authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }).replace(
      `Destination="${SSO_URL}"`,
      `Destination="${SSO_URL}" Extra="value"`,
    );
    expect(() => parseSamlAuthnRequest(xml)).toThrow();
  });

  test("rejects numeric character references", async () => {
    const xml = authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }).replace(
      "<saml:Issuer>",
      "<saml:Issuer>&",
    );
    void xml;
    const attack = authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" });
    const withRef = attack.replace(SP_ENTITY_ID, SP_ENTITY_ID + "&#x41;");
    expect(() => parseSamlAuthnRequest(withRef)).toThrow();
  });

  test("rejects DOCTYPE and comments", async () => {
    expect(() =>
      parseSamlAuthnRequest(`<!DOCTYPE x>${authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" })}`),
    ).toThrow();
    expect(() =>
      parseSamlAuthnRequest(authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" }) + "<!-- injected -->"),
    ).toThrow();
  });

  test("rejects unexpected child elements", async () => {
    const base = authnRequestXml({ issueInstant: "2026-11-09T11:59:00Z" });
    expect(() => parseSamlAuthnRequest(base)).not.toThrow();
    const withExtensions = base.replace(
      "</samlp:AuthnRequest>",
      "<samlp:Extensions/></samlp:AuthnRequest>",
    );
    expect(() => parseSamlAuthnRequest(withExtensions)).toThrow();
  });

  test("rejects an invalid timestamp", async () => {
    expect(() => parseSamlAuthnRequest(authnRequestXml({ issueInstant: "yesterday" }))).toThrow();
  });
});

describe("SAML IdP metadata", () => {
  test("publishes the entity, endpoint and signing certificate", async () => {
    const sp = await createSpSigning();
    const metadata = buildSamlIdpMetadata({
      entityId: IDP_ENTITY_ID,
      certificate: sp.certificatePem,
      ssoUrl: SSO_URL,
    });
    expect(metadata.startsWith("<md:EntityDescriptor")).toBe(true);
    expect(metadata).toContain(`entityID="${IDP_ENTITY_ID}"`);
    expect(metadata).toContain('WantAuthnRequestsSigned="true"');
    expect(metadata).toContain(`Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${SSO_URL}"`);
    // Only Redirect is supported as a request binding; no POST SSO endpoint is advertised.
    expect(metadata).not.toContain(`SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`);
    // The stored certificate body is embedded without whitespace.
    const body = sp.certificatePem
      .split("-----BEGIN CERTIFICATE-----\n")[1]!
      .split("\n-----END CERTIFICATE-----")[0]!
      .replace(/\n/g, "");
    expect(metadata).toContain(`<ds:X509Certificate>${body}</ds:X509Certificate>`);
    expect(metadata).toContain("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
  });

  test("escapes XML-injected entity identifiers", () => {
    const metadata = buildSamlIdpMetadata({
      entityId: "https://idp.example.com/metadata?a=1&b=2",
      certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
      ssoUrl: SSO_URL,
    });
    expect(metadata).toContain("entityID=\"https://idp.example.com/metadata?a=1&amp;b=2\"");
    expect(metadata).not.toContain("&b=2\"");
  });
});

describe("SSO login page", () => {
  test("signs in via the better-auth email or username endpoint and reloads", () => {
    const page = buildSsoLoginPage({ title: "Sign in to continue", hint: "Authenticate to continue." });
    expect(page).toContain("/api/auth/sign-in/email");
    expect(page).toContain("/api/auth/sign-in/username");
    expect(page).toContain("location.reload()");
    // The passkey ceremony uses the plugin endpoints with the standard API.
    expect(page).toContain("/api/auth/passkey/generate-authenticate-options");
    expect(page).toContain("/api/auth/passkey/verify-authentication");
    expect(page).toContain("navigator.credentials.get");
    // The page never navigates away or includes external content.
    expect(page).not.toMatch(/location\.href|window\.open|http:\/\/|https:\/\//);
    // The form itself posts nothing; the fetch call is same-origin.
    expect(page).toContain("credentials:'same-origin'");
    expect(page).not.toContain("<h1>&lt;"); // no double-escaping of copy
  });

  test("escapes page copy", () => {
    const page = buildSsoLoginPage({ title: 'Title "quoted" & <tag>', hint: "ok" });
    expect(page).toContain("Title &quot;quoted&quot; &amp; &lt;tag&gt;");
  });
});

describe("SP-side response verification from published metadata", () => {
  test("a service provider configured only from metadata verifies the signed response", async () => {
    // The IdP publishes metadata; the SP derives its single trust point from it.
    const idp = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ["sign", "verify"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", idp.privateKey));
    const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${(base64(pkcs8).match(/.{1,64}/g) ?? []).join("\n")}\n-----END PRIVATE KEY-----\n`;
    const imported = await importSamlIdpPrivateKey(pkcs8Pem);
    const idpCertificatePem = await certificatePemFor(idp as unknown as CryptoKeyPair);
    const metadata = buildSamlIdpMetadata({
      entityId: IDP_ENTITY_ID,
      certificate: idpCertificatePem,
      ssoUrl: SSO_URL,
    });
    const certificateBody = metadata
      .split("<ds:X509Certificate>")[1]!
      .split("</ds:X509Certificate>")[0]!
      .split("\n")
      .join("");
    const metadataTrustedKey = await importSamlServiceProviderTrustedKey(
      `-----BEGIN CERTIFICATE-----\n${certificateBody}\n-----END CERTIFICATE-----\n`,
    );

    const issued: IssuedSamlResponse = await buildSignedSamlResponse({
      requestId: "_authn-1",
      acsUrl: ACS_URL,
      serviceProviderEntityId: SP_ENTITY_ID,
      relayState: "relay-state-1",
      subject: { nameId: "user@example.com", sessionId: "sess-1", authenticatedAt: new Date(NOW.getTime() - 60_000) },
      signing: { entityId: IDP_ENTITY_ID, certificate: idpCertificatePem, privateKey: imported },
      now: NOW,
    });
    const responseXml = atob(issued.samlResponse);
    expect(responseXml).toContain(`NotOnOrAfter="${new Date(NOW.getTime() + 300_000).toISOString().replace(/\.\d{3}Z$/, "Z")}"`);
    const signedInfo = responseXml.slice(
      responseXml.indexOf("<ds:SignedInfo"),
      responseXml.indexOf("</ds:SignedInfo>") + "</ds:SignedInfo>".length,
    );
    const signatureValue = responseXml.slice(
      responseXml.indexOf("<ds:SignatureValue>") + "<ds:SignatureValue>".length,
      responseXml.indexOf("</ds:SignatureValue>"),
    );
    const signatureBytes = Uint8Array.from(atob(signatureValue), (char) => char.charCodeAt(0));
    const verified = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      metadataTrustedKey,
      signatureBytes,
      new TextEncoder().encode(signedInfo),
    );
    expect(verified).toBe(true);

    // The POST page carries the relay state from the original request.
    expect(issued.postPage).toContain('name="RelayState" value="relay-state-1"');
  });
});

describe("Signed response round trip", () => {
  function extract(responseXml: string, opening: string, closing: string): string {
    const start = responseXml.indexOf(opening);
    const end = responseXml.indexOf(closing, start) + closing.length;
    return responseXml.slice(start, end);
  }

  test("signature and digest verify against the generated key", async () => {
    const idp = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ["sign", "verify"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", idp.privateKey));
    const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${(base64(pkcs8).match(/.{1,64}/g) ?? []).join("\n")}\n-----END PRIVATE KEY-----\n`;
    const imported = await importSamlIdpPrivateKey(pkcs8Pem);
    expect(imported.algorithm.name).toBe("RSASSA-PKCS1-v1_5");
    const idpCertificatePem = await certificatePemFor(idp as unknown as CryptoKeyPair);

    const issued: IssuedSamlResponse = await buildSignedSamlResponse({
      requestId: "_authn-1",
      acsUrl: ACS_URL,
      serviceProviderEntityId: SP_ENTITY_ID,
      relayState: null,
      subject: { nameId: "user@example.com", sessionId: "sess-1", authenticatedAt: new Date(NOW.getTime() - 60_000) },
      signing: { entityId: IDP_ENTITY_ID, certificate: idpCertificatePem, privateKey: imported },
      now: NOW,
    });
    const responseXml = atob(issued.samlResponse);
    expect(responseXml).toContain('InResponseTo="_authn-1"');
    expect(responseXml).toContain(`Recipient="${ACS_URL}"`);
    expect(responseXml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
    expect(responseXml).toContain("<saml:NameID");
    expect(atob(issued.samlResponse)).toBe(responseXml);

    // The SignedInfo bytes must be exactly the canonical string as signed.
    const signedInfo = extract(responseXml, "<ds:SignedInfo", "</ds:SignedInfo>");
    const signatureValue = extract(responseXml, "<ds:SignatureValue>", "</ds:SignatureValue>")
      .replace("<ds:SignatureValue>", "")
      .replace("</ds:SignatureValue>", "");
    const signatureBytes = Uint8Array.from(atob(signatureValue), (char) => char.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      idp.publicKey,
      signatureBytes,
      new TextEncoder().encode(signedInfo),
    );
    expect(valid).toBe(true);

    // Digest: assertion minus the enveloped Signature element.
    const assertionWithSignature = extract(responseXml, "<saml:Assertion", "</saml:Assertion>");
    const signatureElement = extract(responseXml, "<ds:Signature", "</ds:Signature>");
    const digestValue = extract(responseXml, "<ds:DigestValue>", "</ds:DigestValue>")
      .replace("<ds:DigestValue>", "")
      .replace("</ds:DigestValue>", "");
    const coreAssertion = assertionWithSignature.replace(signatureElement, "");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(coreAssertion));
    expect(base64(new Uint8Array(digest))).toBe(digestValue);

    // The post page delivers the same encoded response to the ACS.
    expect(issued.postPage).toContain(`action="${ACS_URL}"`);
    expect(issued.postPage).toContain(issued.samlResponse);
  });
});
