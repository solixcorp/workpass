/**
 * SAML Response/Assertion construction and signing for the POST binding.
 * The XML is built canonically by construction so the signed byte ranges are
 * exactly the strings produced here: attributes are emitted in canonical
 * sorted order, namespaces the signed element visibly uses are declared
 * directly on it, and no whitespace is introduced inside signed elements.
 */

import { escapeSamlAttribute, escapeSamlText, escapeSamlXml } from "./request-binding";
import { pemCertificateDerBase64 } from "./certificates";

const ASSERTION_URN = "urn:oasis:names:tc:SAML:2.0:assertion";
const PROTOCOL_URN = "urn:oasis:names:tc:SAML:2.0:protocol";
const DS_URN = "http://www.w3.org/2000/09/xmldsig#";
const C14N_URN = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_TRANSFORM_URN = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SHA256_DIGEST_URN = "http://www.w3.org/2001/04/xmlenc#sha256";
const RSA_SHA256_URN = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const NAMEID_EMAIL_URN = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const BEARER_URN = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const UNSPECIFIED_AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

export interface SamlSigningMaterial {
  entityId: string;
  /** PEM certificate matching the private key, for ds:KeyInfo. */
  certificate: string;
  /** RSA private key imported with RSASSA-PKCS1-v1_5 / SHA-256 sign usage. */
  privateKey: CryptoKey;
  /** Published during a rotation overlap window; verifies both key pairs. */
  previousCertificate?: string;
}

export interface SamlResponseSubject {
  /** NameID value, typically the verified account email address. */
  nameId: string;
  sessionId: string;
  authenticatedAt: Date;
}

export interface SamlResponseParams {
  requestId: string;
  /** Assertion consumer destination copied from the verified registration. */
  acsUrl: string;
  /** SP entity id used as the valid Audience. */
  serviceProviderEntityId: string;
  relayState: string | null;
  subject: SamlResponseSubject;
  signing: SamlSigningMaterial;
  /** Default sign-in method class; overridable once MFA policy is decided. */
  authnClass?: string;
  now?: Date;
}

export interface IssuedSamlResponse {
  samlResponse: string;
  postPage: string;
}

function formatSamlInstant(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function generateXmlId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let value = "id";
  for (const byte of bytes) value += byte.toString(16).padStart(2, "0");
  return value;
}

/**
 * Build the full signed Response with an enveloped signature over the
 * Assertion. The assertion is signed, not the response itself; interop with a
 * real service provider is verified in a dedicated task before enablement.
 */
export async function buildSignedSamlResponse(
  params: SamlResponseParams,
): Promise<IssuedSamlResponse> {
  const now = params.now ?? new Date();
  const issueInstant = formatSamlInstant(now);
  const notBefore = formatSamlInstant(new Date(now.getTime() - 30_000));
  const notOnOrAfter = formatSamlInstant(new Date(now.getTime() + 5 * 60_000));
  const responseId = generateXmlId();
  const assertionId = generateXmlId();
  const authnClass = params.authnClass ?? UNSPECIFIED_AUTHN_CONTEXT;

  const coreAssertion =
    `<saml:Assertion xmlns:saml="${ASSERTION_URN}" ID="${assertionId}" IssueInstant="${issueInstant}" Version="2.0">` +
    `<saml:Issuer>${escapeSamlText(params.signing.entityId)}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="${NAMEID_EMAIL_URN}">${escapeSamlText(params.subject.nameId)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="${BEARER_URN}">` +
    `<saml:SubjectConfirmationData InResponseTo="${escapeSamlAttribute(params.requestId)}" NotOnOrAfter="${notOnOrAfter}" Recipient="${escapeSamlAttribute(params.acsUrl)}"></saml:SubjectConfirmationData>` +
    `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${escapeSamlText(params.serviceProviderEntityId)}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${formatSamlInstant(params.subject.authenticatedAt)}" SessionIndex="${assertionId}">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>${authnClass}</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `</saml:Assertion>`;

  const digestBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(coreAssertion));
  const digestValue = btoa(String.fromCharCode(...new Uint8Array(digestBytes)));
  const signedInfo =
    `<ds:SignedInfo xmlns:ds="${DS_URN}">` +
    `<ds:CanonicalizationMethod Algorithm="${C14N_URN}"></ds:CanonicalizationMethod>` +
    `<ds:SignatureMethod Algorithm="${RSA_SHA256_URN}"></ds:SignatureMethod>` +
    `<ds:Reference URI="#${assertionId}">` +
    `<ds:Transforms>` +
    `<ds:Transform Algorithm="${ENVELOPED_TRANSFORM_URN}"></ds:Transform>` +
    `<ds:Transform Algorithm="${C14N_URN}"></ds:Transform>` +
    `</ds:Transforms>` +
    `<ds:DigestMethod Algorithm="${SHA256_DIGEST_URN}"></ds:DigestMethod>` +
    `<ds:DigestValue>${digestValue}</ds:DigestValue>` +
    `</ds:Reference>` +
    `</ds:SignedInfo>`;

  const signatureBytes = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    params.signing.privateKey,
    new TextEncoder().encode(signedInfo),
  );
  const signatureValue = btoa(String.fromCharCode(...new Uint8Array(signatureBytes)));
  const certificateBase64 = pemCertificateDerBase64(params.signing.certificate);
  const signature =
    `<ds:Signature xmlns:ds="${DS_URN}">` +
    signedInfo +
    `<ds:SignatureValue>${signatureValue}</ds:SignatureValue>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certificateBase64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `</ds:Signature>`;

  // The enveloped-signature transform removes exactly this Signature element,
  // so the SP recomputes the digest over coreAssertion's canonical form.
  const signedAssertion = coreAssertion.replace(
    "</saml:Issuer>",
    `</saml:Issuer>${signature}`,
  );
  const response =
    `<samlp:Response xmlns:samlp="${PROTOCOL_URN}" xmlns:saml="${ASSERTION_URN}" ` +
    `Destination="${escapeSamlAttribute(params.acsUrl)}" ID="${responseId}" ` +
    `InResponseTo="${escapeSamlAttribute(params.requestId)}" IssueInstant="${issueInstant}" Version="2.0">` +
    `<saml:Issuer>${escapeSamlText(params.signing.entityId)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${STATUS_SUCCESS}"/></samlp:Status>` +
    signedAssertion +
    `</samlp:Response>`;
  return { samlResponse: encodeUtf8Base64(response), postPage: buildPostBindingPage(params, response) };
}

function encodeUtf8Base64(value: string): string {
  let binary = "";
  for (const byte of new TextEncoder().encode(value)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function buildPostBindingPage(params: SamlResponseParams, responseXml: string): string {
  const acs = escapeSamlXml(params.acsUrl);
  const relay = params.relayState === null
    ? ""
    : `<input type="hidden" name="RelayState" value="${escapeSamlXml(params.relayState)}"/>`;
  return [
    "<!DOCTYPE html>",
    '<html lang="en"><head><meta charset="utf-8"/>',
    '<title>Continue to your application</title>',
    "</head><body onload=\"document.forms[0].submit()\">",
    `<form method="post" action="${acs}">`,
    `<input type="hidden" name="SAMLResponse" value="${encodeUtf8Base64(responseXml)}"/>`,
    relay,
    "<noscript><button type=\"submit\">Continue</button></noscript>",
    "</form></body></html>",
  ].join("");
}
