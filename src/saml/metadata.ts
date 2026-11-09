/**
 * SAML 2.0 metadata document for this identity provider. The document is
 * public, unsigned protocol metadata: the entity ID, the signing certificate,
 * and the single sign-on endpoint. It is published only for service provider
 * configuration and contains no private material.
 */

import { pemCertificateDerBase64 } from "./certificates";

const MD_URN = "urn:oasis:names:tc:SAML:2.0:metadata";
const DS_URN = "http://www.w3.org/2000/09/xmldsig#";
const PROTOCOL_URN = "urn:oasis:names:tc:SAML:2.0:protocol";
const REDIRECT_BINDING_URN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const NAMEID_EMAIL_URN = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

export function buildSamlIdpMetadata(options: {
  entityId: string;
  certificate: string;
  ssoUrl: string;
}): string {
  const certificateBase64 = pemCertificateDerBase64(options.certificate);
  const entityId = xmlEscape(options.entityId);
  const ssoUrl = xmlEscape(options.ssoUrl);
  return (
    `<md:EntityDescriptor xmlns:md="${MD_URN}" entityID="${entityId}">` +
    `<md:IDPSSODescriptor protocolSupportEnumeration="${PROTOCOL_URN}" WantAuthnRequestsSigned="true">` +
    `<md:KeyDescriptor use="signing">` +
    `<ds:KeyInfo xmlns:ds="${DS_URN}">` +
    `<ds:X509Data><ds:X509Certificate>${certificateBase64}</ds:X509Certificate></ds:X509Data>` +
    `</ds:KeyInfo>` +
    `</md:KeyDescriptor>` +
    `<md:NameIDFormat>${NAMEID_EMAIL_URN}</md:NameIDFormat>` +
    `<md:SingleSignOnService Binding="${REDIRECT_BINDING_URN}" Location="${ssoUrl}"/>` +
    `</md:IDPSSODescriptor>` +
    `</md:EntityDescriptor>`
  );
}

function xmlEscape(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&apos;";
    }
  });
}
