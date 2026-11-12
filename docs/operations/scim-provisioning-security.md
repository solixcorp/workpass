# SCIM provisioning endpoint security

Applies to administrator-configured per-application outbound targets described in
[app provisioning](../design/app-provisioning.md). Deployment/network operators
own the egress policy; an accepted URL or successful connection test is not proof
that the destination is safe.

## URL guard and residual risk

`validProvisioningUrl` in `src/provisioning/routes.ts` requires HTTPS and rejects
embedded credentials, query strings, fragments, IPv6 literals, `localhost`,
`.localhost` and `.local` names. It also rejects IPv4 literals in the enumerated
private, loopback, link-local, shared-address, multicast and reserved ranges.
It is a syntactic guard, not a complete public-address classification or a
destination allowlist. SCIM requests do not follow redirects.

The guard does not resolve hostnames, pin resolved addresses, or control Worker
egress at connection time. A party controlling DNS for a configured SCIM hostname
may change its answers after configuration and steer authenticated provisioning
traffic toward a private service reachable through the deployment's network.
This DNS-rebinding residual (`scim.provisioning.dns-rebinding`) needs validation
against the actual deployment; source review alone cannot establish that egress
is restricted. HTTPS is necessary but does not replace network isolation.

## Operator-owned controls

Before enabling a target or sending a connection test:

- Restrict outbound access to approved SCIM destinations with a deployment-level
  egress allowlist that constrains the actual connection destination, not only
  the configured hostname. Deny private/local destinations unless explicitly
  approved and isolated for the integration.
- Review any private-connect routes or equivalent private-network connectivity
  available to the Worker. Remove unnecessary routes or restrict them to the
  intended service; do not assume public Worker hosting excludes private access.
- Require TLS-valid public endpoints for ordinary outbound SCIM integrations.
  Verify that the certificate is valid for the configured hostname, has a trusted
  chain, and is within its validity period. Do not disable certificate validation;
  a valid hostname certificate alone does not prove the resolved address is public.
- Record the responsible operator, approved destination, effective egress/routing
  policy and owner-observed validation evidence. If those controls cannot be
  established, leave provisioning disabled rather than treating the URL guard as
  sufficient protection.

Periodically revalidate hostname ownership, DNS destinations, certificate validity
and effective egress/private-route restrictions, and repeat the review after DNS,
certificate, target or network configuration changes. Use operator-owned
configuration and approved service observations; do not send provisioning tokens
to unapproved destinations. Disable the target while unexpected changes are
reviewed. Connection-test success does not close the DNS-rebinding residual.
