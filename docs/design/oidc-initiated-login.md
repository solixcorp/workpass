# OIDC third-party-initiated login

For an OIDC application, configure `launchUrl` as the app's login initiation endpoint (`initiate_login_uri`). The signed-in portal's `GET /api/applications` returns that URL with `iss` set to this IdP's discovery `issuer`, and sets `launchInitiatesLogin` to `true`. No `login_hint` is sent. WorkPass's own dashboard and non-OIDC applications keep their original URLs; an OIDC app without a launch URL remains unlaunchable this way.

The app must implement the initiation endpoint. On GET, it must verify that `iss` exactly matches its configured expected issuer, then start a normal authorization code flow with PKCE, using its own state and nonce, at `/oauth2/v1/authorize` or the discovery document's `authorization_endpoint`. The app must validate the authorization response and tokens as usual.

The IdP cannot push tokens to an application without the application starting the authorization request. Adding a launch URL alone does not implement login on the app's side.
