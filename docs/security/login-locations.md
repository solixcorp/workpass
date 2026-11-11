# Sign-in places

Administrators define named **places** (a centre and a radius) and a **policy** that limits sign-in to
people who are near one of them. It is managed in the console under "로그인 위치" and stored in
`location_places`, `location_policy` (one row) and `location_proofs`.

## What is checked, and where

| Sign-in | Checked | If refused |
|---|---|---|
| Password (OPAQUE finish) | After the password proof succeeded, before a session exists | `403` with `code: "location_denied"`; the screen says the place is the reason. A wrong password is still a plain `401`, so the place is never named to someone who has not proven the password. |
| Passkey | After the passkey verified; the new session is deleted | `403` with `code: "location_denied"` |
| App sign-in start (`/api/auth/oauth2/authorize`) | For an existing session | A browser that could still prove its position is sent to `/location?redirect=…` and back; otherwise the access-denied page |

Plaintext username/email password sign-in (`ALLOW_PLAINTEXT_PASSWORD_LOGIN`, test use only) is not checked.

The sign-in screen is told by the server: when the policy enforces, uses the browser, and this browser is
not yet cleared, `/idp/idx/introspect` answers with a `verify-location` remediation (`ui.action:
"share-location"`) before the identify step. Nothing in that decision depends on an account, so it reveals
nothing about one. `introspect` accepts `{ skipLocation: true }` so an exempt account can go on; the
authoritative check is the one at the end.

## Signals and how far to trust them

- **Network** — the position Cloudflare derives from the client address (`request.cf`). The visitor cannot
  set it. It is coarse (a city, often tens of kilometres) and a VPN or mobile carrier gateway moves it, so
  a margin (`networkMarginKm`, default 30) is added to a place's radius. When the platform gives no
  position (for example some local setups), this signal cannot pass.
- **Browser** — the position the browser reports after the person allows it. It is precise, but it comes
  from the person's own device and can be faked. The server accepts it only if its accuracy is within
  `maxAccuracyM` and it lies inside a place's radius, then keeps *only* a random token (as the HttpOnly
  cookie `wp_location`, 15 minutes) and the matched place; the coordinates are not stored. At most 30 proofs
  per address per 10 minutes.
- `network_or_browser` passes on the network position and otherwise asks for the browser's.

This lowers the chance of sign-in from somewhere unexpected; it is not proof of where someone is.

## Modes and safety

- `off`, `observe` (never blocks; writes `authentication.location.observe`), `enforce` (blocks and writes
  `authentication.location.denied`). Start with `observe` and read the log.
- `enforce` is refused if there is no enabled place, or if the administrator saving it would themself be
  refused from their current connection (they can first share their browser position, or exempt a group).
- Members of **exempt groups** pass regardless of position.
- With no enabled place nobody is limited.

## API

Administrator: `GET /api/admin/location` (policy, places, groups, whether the edge gives a position, and how
the caller's own connection fares), `PUT /api/admin/location/policy`, `POST|PUT|DELETE
/api/admin/location/places[/:id]`. Public: `GET /api/location/status`, `POST /api/location/proof`
(`{ latitude, longitude, accuracy }`, same origin only).
