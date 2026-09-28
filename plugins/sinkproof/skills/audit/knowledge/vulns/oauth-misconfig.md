# OAuth / OIDC Misconfiguration
CWE-287 · OWASP A07:2021 · ASVS V5.1.5

## What it is
An OAuth2/OIDC client or authorization server is configured or implemented incorrectly, letting an attacker redirect the auth code/token to a server they control, replay a login, or skip state/nonce validation and hijack a login flow (CSRF on the OAuth callback).

ASVS 4.0.3 has no OAuth-client requirement; V5.1.5 (redirect allow-list) is the closest fit.

## Where to look
- Client registration: `redirect_uri` validation — exact allow-list match vs. prefix/substring match, wildcard subdomains.
- Callback handler: does it validate `state` matches a per-session value generated before the redirect (CSRF protection), and for OIDC, is `nonce` checked against the id_token?
- Token exchange: is the authorization code exchanged over a server-to-server call with `client_secret`/PKCE, or trusted from a client-supplied token directly?
- Scope handling: does the server enforce the scopes it granted, or trust whatever scope the client claims later?
- Account linking: when logging in via OAuth, is the returned email/identity used to silently link to an existing local account without verifying email ownership?
- Common libraries: Passport.js strategies, `django-allauth`, Devise/OmniAuth, Spring Security OAuth2 client config (`redirect-uri-template`).

## How to confirm
Check the callback route for `state` generation/comparison and PKCE (`code_verifier`/`code_challenge`) usage, and check the redirect_uri allow-list logic for exact matching. Report when `state` is not generated per-session and verified, when redirect_uri matching allows attacker-controlled hosts (open redirect into the OAuth flow), or when account linking trusts an unverified email from the provider.

## False-positive traps
- Public clients (SPAs, mobile) using PKCE don't need a `client_secret` — don't flag its absence as a finding if PKCE is present and enforced server-side.
- OmniAuth and django-allauth check `state` by default; Passport OAuth2 strategies only do so with `state: true` or `pkce: true` explicitly configured — confirm the app didn't disable or omit it, don't assume it's checked just because a well-known library is used.
- A redirect_uri allow-list with multiple exact-match entries for legitimate environments (dev/staging/prod) is normal, not a wildcard misconfiguration.
- Identity providers that verify email ownership themselves (e.g. requiring verified email scope) reduce, but don't eliminate, the need to check `email_verified` before auto-linking.

## Safe patterns
```js
app.get("/auth/callback", async (req, res) => {
  const { state, code } = req.query;
  if (state !== req.session.oauthState) return res.sendStatus(400);
  const tokens = await exchangeCode(code, req.session.pkceVerifier);
  const claims = verifyIdToken(tokens.id_token, { nonce: req.session.oauthNonce });
  if (!claims.email_verified) return res.sendStatus(403);
  ...
});
```

## Fix guidance
Generate a unique, unguessable `state` per login attempt, store it server-side (session), and verify it on callback before exchanging the code. Use PKCE for public clients. Validate `redirect_uri` against an exact allow-list, never prefix/substring matching. Only auto-link accounts by a provider-verified email, and require explicit confirmation otherwise.

## Severity guide
- Impact `high`: missing state/PKCE validation or open redirect_uri allows full account takeover via the OAuth flow.
- Impact `medium`: account linking on unverified email allows impersonation of a specific victim who hasn't registered elsewhere.
- Impact `low`: configuration weakness with no demonstrated takeover path (e.g. missing nonce check with state still enforced).
- Exploitability: `high` when the flaw is reachable by tricking any victim into clicking a crafted link; `medium` when it requires the victim to have a specific pre-existing account state.
