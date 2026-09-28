# Missing Security Headers
CWE-693 · OWASP A05:2021 · ASVS V14.4.3

## What it is
The application omits HTTP response headers that constrain how browsers handle the page — Content-Security-Policy (CSP), `X-Frame-Options`/`frame-ancestors`, `Strict-Transport-Security` (HSTS), and `X-Content-Type-Options` — reducing the browser-side defenses available if another bug is exploited. Session-cookie flags (`HttpOnly`/`Secure`) belong to `session-management`, and `SameSite` as a CSRF control belongs to `csrf` — don't duplicate those findings here.

OWASP Top 10 2021 does not map CWE-693 to a category; A05 Security Misconfiguration is the closest fit.

## Where to look
- Node/Express: absence of `helmet()` or manual headers; check `app.use` for `helmet` and its config (`contentSecurityPolicy: false` disables CSP).
- Next.js: `headers()` in `next.config.js`, or a missing `middleware.ts` setting security headers.
- Python: Flask `flask-talisman`, Django `SECURE_*` settings (`SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_SECURE`).
- Rails: `config.force_ssl`, `config.action_dispatch.default_headers`, `secure_headers` gem.
- Java/Spring: `HttpSecurity#headers()` configuration, or Spring Security defaults being overridden/disabled.
- Reverse proxy/CDN config (nginx `add_header`, CloudFront response headers policy) — headers are often set there instead of app code.

## How to confirm
Check the actual response headers (via the framework's security middleware config, or a live request) for the relevant endpoints, not just the presence of a library import — a library can be installed but disabled or misconfigured. Note which headers are missing and on which response types (HTML pages vs. JSON APIs; some headers only matter for HTML).

## False-positive traps
- JSON/API-only endpoints that are never rendered as HTML don't need CSP or `X-Frame-Options`; check `Content-Type` and whether the endpoint is ever loaded in a browser frame.
- Headers set by a CDN, load balancer, or reverse proxy in front of the app are real even if absent from application code — verify the actual deployed response before flagging.
- A missing header is a hardening gap on its own, not proof of an exploitable bug; do not assign it a severity as if it were the vulnerability it would have mitigated.
- `X-XSS-Protection` is deprecated and its absence is not a finding in modern browsers; don't flag it.
- `helmet()` used with its defaults (no options object, or options that don't disable a directive) already sets CSP, HSTS, `X-Content-Type-Options: nosniff`, and frameguard — check the actual config before flagging any of these as missing.

## Safe patterns
```js
app.use(helmet({
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: "deny" },
}));
```

## Fix guidance
Set CSP scoped to the app's actual script/style/image sources; set `Strict-Transport-Security` with a long `max-age` on HTTPS-only sites; set `X-Content-Type-Options: nosniff`; set `frame-ancestors 'none'` (or `X-Frame-Options: DENY`) unless framing is required. Prefer a maintained middleware (Helmet, Talisman, secure_headers) over hand-rolled headers; see `session-management` and `csrf` for cookie flag guidance.

## Severity guide
- Impact `high`: not applicable on its own — a missing header alone does not directly compromise data; if it enables a specific exploit chain, report that chain (e.g. XSS) as high, and cite the missing header as a contributing factor.
- Impact `medium`: a missing header raises the impact of a genuinely reported finding elsewhere — e.g. missing CSP alongside a found XSS makes that XSS's impact `high` instead of `medium`; missing `frame-ancestors` alongside sensitive actions reachable via clickjacking.
- Impact `low`: a missing header with no other exploitable finding depending on it — the default when reporting security headers standalone.
- Exploitability: `low` — the header's absence is not itself exploitable; it only removes a layer of defense that another finding's exploitability depends on.
