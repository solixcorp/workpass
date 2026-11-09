# SAML IdP foundation

The application migration creates a service-provider registration table and the backend has a registration data model and input validation. No endpoint creates or enables a service provider, accepts an AuthnRequest, signs a response, or issues an assertion. The `enabled` field alone does not enable any SAML flow.

Samlify documents IdP response generation and signed request validation, but it is a Node.js library and requires an XML schema validator. Workers support for the complete dependency tree and validator has not been demonstrated. Do not skip schema validation, invent XML signature verification, or deploy a partially implemented SAML login path. A Workers-compatible library and validator, signing-key lifecycle, replay protection, request/ACS validation, authorization policy, and signed-response interoperability with a real test service provider remain required.
