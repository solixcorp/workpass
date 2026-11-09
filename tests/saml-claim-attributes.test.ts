import { describe, expect, test } from "bun:test";
import { buildSignedSamlResponse, type IssuedSamlResponse } from "../src/saml/assertion";
import {
  importSamlIdpPrivateKey,
  importSamlServiceProviderTrustedKey,
} from "../src/saml/certificates";
import { buildCertificateDer, derToPem } from "./saml-x509";

const SP_ENTITY_ID = "https://sp.example.com/metadata";
const IDP_ENTITY_ID = "https://idp.example.com/metadata";
const ACS_URL = "https://sp.example.com/acs";
const NOW = new Date("2026-11-09T12:00:00Z");

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function createIdpSigning(): Promise<{ entityId: string; certificate: string; privateKey: CryptoKey }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  );
  const exportJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const realModulus = Array.from(atob(exportJwk.n!.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0) & 0xff);
  const realExponent = Array.from(atob(exportJwk.e!), (char) => char.charCodeAt(0) & 0xff);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${(base64(pkcs8).match(/.{1,64}/g) ?? []).join("\n")}\n-----END PRIVATE KEY-----\n`;
  return {
    entityId: IDP_ENTITY_ID,
    certificate: derToPem(buildCertificateDer(new Uint8Array(realModulus), new Uint8Array(realExponent))),
    privateKey: await importSamlIdpPrivateKey(pkcs8Pem),
  };
}

function extract(responseXml: string, opening: string, closing: string): string {
  const start = responseXml.indexOf(opening);
  const end = responseXml.indexOf(closing, start) + closing.length;
  return responseXml.slice(start, end);
}

async function issueWith(attributes: Array<{ name: string; value: string }>): Promise<IssuedSamlResponse> {
  const signing = await createIdpSigning();
  return await buildSignedSamlResponse({
    requestId: "_authn-1",
    acsUrl: ACS_URL,
    serviceProviderEntityId: SP_ENTITY_ID,
    relayState: null,
    subject: { nameId: "user@example.com", sessionId: "sess-1", authenticatedAt: new Date(NOW.getTime() - 60_000) },
    signing,
    now: NOW,
    attributes,
  });
}

describe("released SAML attributes", () => {
  test("the attribute statement carries sorted, escaped, simple-typed values", async () => {
    const issued = await issueWith([
      { name: "z-last", value: "2" },
      { name: "https://auth.example.test/claims/active-account-name", value: "platform" },
      { name: "https://auth.example.test/claims/attributes/team", value: "R&D <core>" },
    ]);
    const responseXml = atob(issued.samlResponse);
    const statement = extract(responseXml, "<saml:AttributeStatement", "</saml:AttributeStatement>");
    // Attributes come back in canonical sorted order regardless of input order.
    const accountNameAt = statement.indexOf("active-account-name");
    const teamAt = statement.indexOf("attributes/team");
    const lastAt = statement.indexOf("z-last");
    expect(accountNameAt).toBeGreaterThan(0);
    expect(accountNameAt).toBeLessThan(teamAt);
    expect(teamAt).toBeLessThan(lastAt);
    expect(statement).toContain('NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"');
    expect(statement).toContain(`xsi:type="xs:string"`);
    // Values are XML-escaped exactly like the rest of the builder.
    expect(statement).toContain("R&amp;D &lt;core&gt;");
    // The statement sits between Conditions and AuthnStatement.
    const conditions = responseXml.indexOf("</saml:Conditions>");
    expect(responseXml.indexOf("<saml:AttributeStatement")).toBeGreaterThan(conditions);
    expect(responseXml.indexOf("<saml:AuthnStatement")).toBeGreaterThan(responseXml.indexOf("</saml:AttributeStatement>"));
  });

  test("the signature and digest still verify with attributes present", async () => {
    const signing = await createIdpSigning();
    const issued = await buildSignedSamlResponse({
      requestId: "_authn-1",
      acsUrl: ACS_URL,
      serviceProviderEntityId: SP_ENTITY_ID,
      relayState: null,
      subject: { nameId: "user@example.com", sessionId: "sess-1", authenticatedAt: new Date(NOW.getTime() - 60_000) },
      signing,
      now: NOW,
      attributes: [
        { name: "https://auth.example.test/claims/active-account-id", value: "acc-1" },
        { name: "https://auth.example.test/claims/attributes/level", value: "3" },
      ],
    });
    const responseXml = atob(issued.samlResponse);
    const signedInfo = extract(responseXml, "<ds:SignedInfo", "</ds:SignedInfo>");
    const signatureValue = extract(responseXml, "<ds:SignatureValue>", "</ds:SignatureValue>")
      .replace("<ds:SignatureValue>", "")
      .replace("</ds:SignatureValue>", "");
    const signatureBytes = Uint8Array.from(atob(signatureValue), (char) => char.charCodeAt(0));
    // The published certificate's public key verifies the SignedInfo bytes.
    const trustedKey = await importSamlServiceProviderTrustedKey(signing.certificate);
    const verified = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      trustedKey,
      signatureBytes,
      new TextEncoder().encode(signedInfo),
    );
    expect(verified).toBe(true);
    // Enveloped-signature invariant: the digest covers the assertion exactly
    // as built, attributes included.
    const assertionWithSignature = extract(responseXml, "<saml:Assertion", "</saml:Assertion>");
    const signatureElement = extract(responseXml, "<ds:Signature", "</ds:Signature>");
    const coreAssertion = assertionWithSignature.replace(signatureElement, "");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(coreAssertion));
    expect(base64(new Uint8Array(digest))).toBe(
      extract(responseXml, "<ds:DigestValue>", "</ds:DigestValue>")
        .replace("<ds:DigestValue>", "")
        .replace("</ds:DigestValue>", ""),
    );
  });

  test("no attribute statement is emitted for an empty release", async () => {
    const issued = await issueWith([]);
    const responseXml = atob(issued.samlResponse);
    expect(responseXml).not.toContain("AttributeStatement");
    // An undefined list behaves the same (claim release disabled).
    const signing = await createIdpSigning();
    const bare = await buildSignedSamlResponse({
      requestId: "_authn-1",
      acsUrl: ACS_URL,
      serviceProviderEntityId: SP_ENTITY_ID,
      relayState: null,
      subject: { nameId: "user@example.com", sessionId: "sess-1", authenticatedAt: new Date(NOW.getTime() - 60_000) },
      signing,
      now: NOW,
    });
    expect(atob(bare.samlResponse)).not.toContain("AttributeStatement");
  });
});
