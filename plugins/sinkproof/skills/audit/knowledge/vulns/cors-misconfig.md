# CORS Misconfiguration
CWE-942 · OWASP A05:2021 · ASVS V14.5.3

## What it is
The server's Cross-Origin Resource Sharing headers let pages on other, untrusted origins read authenticated responses from the API — usually because `Access-Control-Allow-Origin` reflects the request's `Origin` header and is combined with `Access-Control-Allow-Credentials: true`.

## Where to look
- Node/Express: `cors()` middleware configured with `origin: true` or `origin: (origin, cb) => cb(null, origin)`, or manual `res.setHeader("Access-Control-Allow-Origin", req.headers.origin)`.
- Java/Spring: `@CrossOrigin(origins = "*")` combined with credentials, or a `CorsConfiguration` that reflects the origin.
- Rails: `rack-cors` with `origins '*'` and `credentials: true`.
- Django: `django-cors-headers` with `CORS_ALLOW_ALL_ORIGINS = True` and `CORS_ALLOW_CREDENTIALS = True`.
- Go: `cors.New(cors.Options{AllowedOrigins: []string{"*"}, AllowCredentials: true})`.
- Any hand-rolled middleware that echoes the `Origin` request header back into the response.
- Origin checks using an unanchored regex (e.g. `/example\.com/` matching `evil-example.com.attacker.net`) or `origin.endsWith(".example.com")` (matching `evilexample.com` or an attacker-registered `xexample.com`) instead of an exact host/allow-list match.
- Configurations that allow the literal `null` origin (sent by sandboxed iframes, local `file://` pages, and some redirects) alongside credentials.

## How to confirm
Show that `Access-Control-Allow-Origin` is set to a reflected/arbitrary origin (or `*`) at the same time `Access-Control-Allow-Credentials: true` is present, on an endpoint that returns authenticated, user-specific data (cookies or bearer tokens accepted). Browsers reject the `*`+credentials combination outright, so real risk requires the reflected-origin form.

## False-positive traps
- `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials` only exposes data the endpoint would already serve to anonymous requests (e.g. a public API) — usually not a finding.
- An explicit allow-list of specific origins (`https://app.example.com`) is safe even with credentials enabled.
- CORS only affects browser-mediated cross-origin reads; it does not by itself allow server-to-server or same-origin access, and does not replace CSRF protections for state-changing requests.
- A permissive `OPTIONS` preflight response alone, without credentials and without sensitive data in the real response, is low impact.

## Safe patterns
```js
const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED.has(origin)),
  credentials: true,
}));
```

## Fix guidance
Use an explicit allow-list of trusted origins instead of reflecting the request `Origin`; never combine a wildcard or reflected origin with `Allow-Credentials: true`; scope permissive CORS to genuinely public, unauthenticated endpoints only; add `Vary: Origin` when the allowed origin varies per request.

## Severity guide
- Impact `high`: reflected-origin + credentials on an endpoint returning sensitive per-user data (account details, tokens, PII).
- Impact `medium`: reflected-origin + credentials on an endpoint with limited sensitive data, or CORS misconfigured on a state-changing endpoint without other CSRF protection.
- Impact `low`: wildcard origin on a genuinely public, non-credentialed endpoint.
- Exploitability: `high` — any site the victim visits while authenticated can pull the data with a background request.
