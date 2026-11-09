/**
 * WS-Federation passive sign-in for the profile documented in
 * docs/design/wsfed-profile.md: a bearer SAML 1.1 token wrapped in a
 * WS-Trust RequestSecurityTokenResponse, posted to the registered reply URL.
 * The XML is produced canonically by construction with the same rules as the
 * SAML 2.0 response builder, using the shared identity-provider signing pair.
 */

import { escapeSamlAttribute, escapeSamlText } from "../saml/request-binding";
import { pemCertificateDerBase64 } from "../saml/certificates";

const SAML11_URN = "urn:oasis:names:tc:SAML:1.0:assertion";
const DS_URN = "http://www.w3.org/2000/09/xmldsig#";
const C14N_URN = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_TRANSFORM_URN = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256_DIGEST_URN = "http://www.w3.org/2001/04/xmlenc#sha256";
const RSA_SHA256_URN = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const TRUST_URN = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const ISSUE_REQUEST_URN = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
const BEARER_KEY_URN = "http://schemas.xmlsoap.org/ws/2005/02/trust/BearerKey";
const ADDRESSING_URN = "http://www.w3.org/2005/08/addressing";
const PASSWORD_METHOD_URN = "urn:oasis:names:tc:SAML:1.0:am:password";
const NAMEID_EMAIL_URN = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

export interface WsfedSigningMaterial {
  entityId: string;
  certificate: string;
  privateKey: CryptoKey;
}

export interface WsfedSignInParams {
  /** Echoed back bounded and unverified: WS-Federation's wctx is opaque. */
  wctx: string | null;
  /** The registered realm (wtrealm) that the token audience must match. */
  realm: string;
  /** The registered reply URL the token is delivered to. */
  replyUrl: string;
  identity: { nameId: string };
  signing: WsfedSigningMaterial;
  now?: Date;
}

function formatSaml11Instant(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function generateId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let value = prefix;
  for (const byte of bytes) value += byte.toString(16).padStart(2, "0");
  return value;
}

/**
 * Build and sign the complete RequestSecurityTokenResponse (wresult). The
 * assertion carries the enveloped signature over the assertion minus the
 * Signature element, exactly like the SAML 2.0 builder.
 */
export async function buildWsfedSignInResult(params: WsfedSignInParams): Promise<{ wresult: string; postPage: string }> {
  const now = params.now ?? new Date();
  const issueInstant = formatSaml11Instant(now);
  const notBefore = formatSaml11Instant(new Date(now.getTime() - 30_000));
  const notOnOrAfter = formatSaml11Instant(new Date(now.getTime() + 5 * 60_000));
  const assertionId = generateId("id");

  const coreAssertion =
    `<saml:Assertion xmlns:saml="${SAML11_URN}" AssertionID="${assertionId}" IssueInstant="${issueInstant}" Issuer="${escapeSamlAttribute(params.signing.entityId)}" MajorVersion="1" MinorVersion="1">` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestrictionCondition><saml:Audience>${escapeSamlText(params.realm)}</saml:Audience></saml:AudienceRestrictionCondition>` +
    `</saml:Conditions>` +
    `<saml:AuthenticationStatement AuthenticationInstant="${issueInstant}" AuthenticationMethod="${PASSWORD_METHOD_URN}">` +
    `<saml:Subject>` +
    `<saml:NameIdentifier Format="${NAMEID_EMAIL_URN}">${escapeSamlText(params.identity.nameId)}</saml:NameIdentifier>` +
    `<saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `</saml:AuthenticationStatement>` +
    `</saml:Assertion>`;

  const digestBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(coreAssertion));
  let digestBinary = "";
  for (const byte of new Uint8Array(digestBytes)) digestBinary += String.fromCharCode(byte);
  const digestValue = btoa(digestBinary);

  const signedInfo =
    `<ds:SignedInfo xmlns:ds="${DS_URN}">` +
    `<ds:CanonicalizationMethod Algorithm="${C14N_URN}"/>` +
    `<ds:SignatureMethod Algorithm="${RSA_SHA256_URN}"/>` +
    `<ds:Reference URI="#${assertionId}">` +
    `<ds:Transforms>` +
    `<ds:Transform Algorithm="${ENVELOPED_TRANSFORM_URN}"/>` +
    `<ds:Transform Algorithm="${C14N_URN}"/>` +
    `</ds:Transforms>` +
    `<ds:DigestMethod Algorithm="${SHA256_DIGEST_URN}"/>` +
    `<ds:DigestValue>${digestValue}</ds:DigestValue>` +
    `</ds:Reference>` +
    `</ds:SignedInfo>`;

  const signatureBytes = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    params.signing.privateKey,
    new TextEncoder().encode(signedInfo),
  );
  let signatureBinary = "";
  for (const byte of new Uint8Array(signatureBytes)) signatureBinary += String.fromCharCode(byte);
  const signatureValue = btoa(signatureBinary);
  const certificateBase64 = pemCertificateDerBase64(params.signing.certificate);

  const signature =
    `<ds:Signature xmlns:ds="${DS_URN}">` +
    signedInfo +
    `<ds:SignatureValue>${signatureValue}</ds:SignatureValue>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certificateBase64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `</ds:Signature>`;

  // The enveloped-signature transform removes exactly this element, so the
  // relying party recomputes the digest over coreAssertion's canonical form.
  const signedAssertion = coreAssertion.replace("</saml:AuthenticationStatement>", `</saml:AuthenticationStatement>${signature}`);

  const wresult =
    `<t:RequestSecurityTokenResponse xmlns:t="${TRUST_URN}">` +
    `<t:Lifetime>` +
    `<wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${notBefore}</wsu:Created>` +
    `<wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${notOnOrAfter}</wsu:Expires>` +
    `</t:Lifetime>` +
    `<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">` +
    `<wsa:EndpointReference xmlns:wsa="${ADDRESSING_URN}"><wsa:Address>${escapeSamlText(params.realm)}</wsa:Address></wsa:EndpointReference>` +
    `</wsp:AppliesTo>` +
    `<t:RequestedSecurityToken>${signedAssertion}</t:RequestedSecurityToken>` +
    `<t:TokenType>${SAML11_URN}</t:TokenType>` +
    `<t:RequestType>${ISSUE_REQUEST_URN}</t:RequestType>` +
    `<t:KeyType>${BEARER_KEY_URN}</t:KeyType>` +
    `</t:RequestSecurityTokenResponse>`;

  return { wresult, postPage: buildSignInPostPage(params, wresult) };
}

function buildSignInPostPage(params: WsfedSignInParams, wresult: string): string {
  const encoded = new TextEncoder().encode(wresult);
  let wresultBinary = "";
  for (const byte of encoded) wresultBinary += String.fromCharCode(byte);
  const base64Wresult = btoa(wresultBinary);
  const reply = escapeSamlText(params.replyUrl);
  const ctx = params.wctx === null
    ? ""
    : `<input type="hidden" name="wctx" value="${escapeSamlText(params.wctx)}"/>`;
  return [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/><title>Continue to your application</title>',
    "</head><body onload=\"document.forms[0].submit()\">",
    `<form method="post" action="${reply}">`,
    `<input type="hidden" name="wresult" value="${escapeSamlText(base64Wresult)}"/>`,
    ctx,
    "<noscript><button type=\"submit\">Continue</button></noscript>",
    "</form></body></html>",
  ].join("");
}
