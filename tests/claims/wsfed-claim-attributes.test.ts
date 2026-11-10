import { describe, expect, test } from "bun:test";
import { buildWsfedSignInResult } from "../../src/wsfed/token";
import {
  importSamlIdpPrivateKey,
  importSamlServiceProviderTrustedKey,
} from "../../src/saml/certificates";
import { buildCertificateDer, derToPem } from "../saml/saml-x509";

const REALM = "https://rp.example.test/";
const IDP_ENTITY_ID = "https://idp.example.test/metadata";
const NOW = new Date("2026-11-09T12:00:00Z");

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function createIdpSigning() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${(base64(pkcs8).match(/.{1,64}/g) ?? []).join("\n")}\n-----END PRIVATE KEY-----\n`;
  const exportJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const realModulus = Array.from(atob(exportJwk.n!.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0) & 0xff);
  const realExponent = Array.from(atob(exportJwk.e!), (char) => char.charCodeAt(0) & 0xff);
  return {
    entityId: IDP_ENTITY_ID,
    certificate: derToPem(buildCertificateDer(new Uint8Array(realModulus), new Uint8Array(realExponent))),
    privateKey: await importSamlIdpPrivateKey(pkcs8Pem),
  };
}

function extract(xml: string, opening: string, closing: string): string {
  const start = xml.indexOf(opening);
  const end = xml.indexOf(closing, start) + closing.length;
  return xml.slice(start, end);
}

async function issue(attributeRelease?: { namespace: string; attributes: Array<{ name: string; value: string }> }) {
  const signing = await createIdpSigning();
  const issued = await buildWsfedSignInResult({
    wctx: "ctx-1",
    realm: REALM,
    replyUrl: "https://rp.example.test/reply",
    identity: { nameId: "user@example.test" },
    signing,
    now: NOW,
    attributeRelease,
  });
  // wresult is carried in the POST page as escaped base64 bytes.
  const encoded = issued.postPage.split('name="wresult" value="')[1]!.split('"')[0]!;
  const wresultBinary = Uint8Array.from(atob(encoded.replace(/&quot;/g, '"')), (char) => char.charCodeAt(0));
  const wresult = new TextDecoder().decode(wresultBinary);
  return { signing, wresult };
}

describe("WS-Fed released attributes", () => {
  test("no statement is emitted when release is absent or empty", async () => {
    const bare = await issue(undefined);
    expect(bare.wresult).not.toContain("AttributeStatement");
    const empty = await issue({ namespace: "https://auth.example.test/claims", attributes: [] });
    expect(empty.wresult).not.toContain("AttributeStatement");
  });

  test("released attributes land in a SAML 1.1 statement with namespaced names", async () => {
    const { wresult } = await issue({
      namespace: "https://auth.example.test/claims",
      attributes: [
        { name: "active-account-name", value: "platform" },
        { name: "active-account-id", value: "acc-1" },
      ],
    });
    const statement = extract(wresult, "<saml:AttributeStatement>", "</saml:AttributeStatement>");
    // Sorted by name regardless of input order, namespace on every attribute.
    expect(statement.indexOf("active-account-id")).toBeGreaterThan(-1);
    expect(statement.indexOf("active-account-id")).toBeLessThan(statement.indexOf("active-account-name"));
    expect(statement.match(/AttributeNamespace="https:\/\/auth\.example\.test\/claims"/g)?.length).toBe(2);
    expect(statement).toContain("platform");
  });

  test("the signature still verifies and the digest covers released attributes", async () => {
    const { signing, wresult } = await issue({
      namespace: "https://auth.example.test/claims",
      attributes: [{ name: "attributes/team", value: "core" }],
    });
    const signedInfo = extract(wresult, "<ds:SignedInfo", "</ds:SignedInfo>");
    const signatureValue = extract(wresult, "<ds:SignatureValue>", "</ds:SignatureValue>")
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
    const assertion = extract(wresult, "<saml:Assertion", "</saml:Assertion>");
    const signatureElement = extract(wresult, "<ds:Signature", "</ds:Signature>");
    // Enveloped-signature invariant: statement minus Signature covers attributes.
    const coreAssertion = assertion.replace(signatureElement, "");
    const digestBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(coreAssertion));
    expect(base64(new Uint8Array(digestBytes))).toBe(
      extract(wresult, "<ds:DigestValue>", "</ds:DigestValue>")
        .replace("<ds:DigestValue>", "")
        .replace("</ds:DigestValue>", ""),
    );
    expect(signedInfo).toContain(`URI="#`);
  });
});
