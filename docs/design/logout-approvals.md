# Back-channel logout URI approvals

Administrators manage exact approved destination strings with `GET`, `POST`, and `DELETE /api/admin/oidc-logout-approvals`. POST takes `{ "uri": "https://rp.example/logout" }`; DELETE takes the URL-encoded `uri` query parameter. The list includes each URI's `inUseBy` clients. Approval does not enable logout on a client by itself. Addresses must pass the existing back-channel safety validation; they are stored without normalization. A URI used by a client cannot be deleted, and clients cannot use an unapproved URI. Changes are audited. Admin authorization, same-origin mutation checks, and no-store apply.

Approval is not a DNS or network-level egress control: operators must verify destination ownership and enforce appropriate outbound network restrictions.
