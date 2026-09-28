# JWT Authentication Flaws
CWE-347 · OWASP A02:2021 · ASVS V3.5.3

## What it is
A JSON Web Token used for authentication or authorization is trusted without properly verifying its signature and claims, or a privileged claim inside it (`isAdmin`, `role`, `tenant_id`) is trusted at face value without re-checking the source of truth. This lets an attacker forge, replay, or reuse a token to gain access it should not have.

## Where to look
- Any call to a JWT library's decode function: jsonwebtoken's `jwt.decode()` has no verify option at all — it never checks the signature, so any use of it for an authorization decision is a finding regardless of options passed. PyJWT 2.x's `jwt.decode()` verifies the signature by default (must pass `options={"verify_signature": False}` to disable it) — flag only when that option is explicitly set or the algorithm/key handling is wrong.
- Algorithm handling: code that reads `alg` from the token header itself, or accepts both HMAC and RSA/EC algorithms in the same verify call (`algorithms: ['HS256', 'RS256', 'none']`).
- Secret/key source: hardcoded or weak HMAC secrets, secrets shared between environments, missing `exp`/`aud`/`iss` validation options.
- Claim trust: middleware that reads `isAdmin`, `role`, `permissions`, or `tenant_id` straight from the token payload and uses it for an authorization decision without checking the database or a revocation list.
- Refresh/rotation: no token revocation or blacklist on logout/password change/role change, long-lived access tokens with no refresh flow.

## How to confirm
Find where the token is verified and check: (1) a verify call is actually used, not just decode; (2) the algorithm list passed to verify is pinned to one known algorithm — never derived from the token; (3) `exp`, and where applicable `aud`/`iss`, are checked; (4) the signing key/secret is strong and not exposed in source or logs; (5) any privileged claim used for an authorization decision is re-validated against the database (or the token is short-lived and there is a revocation check) rather than trusted purely from the token.

## False-positive traps
- Libraries that verify by default (e.g. `jwt.verify()` vs `jwt.decode()` in jsonwebtoken) are safe as long as `algorithms` is explicitly pinned — check the call, not just the function name.
- A token used only for a non-security purpose (e.g. decoding a claim for display after signature already verified upstream by an API gateway) is not a finding if the gateway's verification is confirmed.
- Short-lived tokens (a few minutes) with no revocation may be an accepted tradeoff — flag as lower severity, not silently ignored.
- Symmetric secrets loaded from a proper secrets manager/env var are fine; only flag hardcoded or clearly weak (short, dictionary) secrets.

## Safe patterns
```js
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"],
  audience: "my-api",
  issuer: "my-auth-service",
});
const user = await db.users.findById(payload.sub);
if (!user || user.role !== "admin") return res.sendStatus(403);
```

## Fix guidance
Always call the library's verify function with an explicit, fixed algorithm allow-list, and validate `exp`, `aud`, and `iss`. Use a strong, secret-manager-stored key (or asymmetric keys with the private key never shipped to verifiers). Treat privileged claims as a cache, not a source of truth: re-check role/permission and revocation status against the database for sensitive actions, or keep access tokens short-lived with a server-side revocation/refresh check.

## Severity guide
- Impact `high`: forged or replayed tokens grant admin access, cross-account access, or bypass authentication entirely.
- Impact `medium`: a privileged claim is trusted without re-check but exploitation requires an already-valid token or a narrow window.
- Impact `low`: weak validation with no practical path to privilege escalation (e.g. missing `aud` check in a single-audience system).
- Exploitability: `high` when an attacker can forge or manipulate a token themselves (algorithm confusion, weak secret); `medium` when they need a leaked or stolen but otherwise valid token.
