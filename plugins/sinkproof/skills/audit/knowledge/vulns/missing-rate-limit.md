# Missing Rate Limiting
CWE-307 · OWASP A07:2021 · ASVS V2.2.1

## What it is
An endpoint that is sensitive to brute-force or enumeration abuse — login, password reset, OTP verification, coupon/code lookup, signup — has no limit on repeated attempts from the same user, IP, or credential, letting an attacker automate guessing or resource exhaustion.

## Where to look
- Auth endpoints: `/login`, `/token`, `/password-reset`, `/verify-otp`, `/mfa/verify`.
- Enumeration-prone endpoints: signup (email-exists checks), coupon/promo code redemption, invite code lookup, username availability.
- Middleware: presence of `express-rate-limit`, `django-ratelimit`/`django-axes`, Rails `rack-attack`, Laravel `throttle` middleware, Spring `Bucket4j`/gateway rate limiting, or a WAF/API-gateway rule (may be outside the repo).
- Account lockout logic: failed-attempt counters tied to the account, not just the IP (IP-only limits are bypassed by rotating IPs).

## How to confirm
Locate the route and check for a rate-limiting middleware/decorator applied to it, and whether it's keyed appropriately. IP-only limiting on login is a weaker control — report it at impact `low`, not as absent protection. Report when a sensitive endpoint has no limiting logic in the repo at all, or when the limit is trivially bypassable (e.g. resets on any header change, keyed only by a client-supplied value).

## False-positive traps
- Rate limiting is very often enforced at the edge (API gateway, CDN/WAF, load balancer) outside the application repo — you usually cannot confirm its absence, only its absence *in this codebase*. Default exploitability to `medium` unless the repo or its infra-as-code clearly shows no such layer exists.
- A generic global rate limiter (e.g. 100 req/min per IP for the whole API) may not be sufficient for a specific high-value endpoint like login — check whether it's endpoint-specific, not just present somewhere.
- CAPTCHA or progressive delay after N failures counts as mitigation even without a hard rate limit — check for it before flagging.
- Some endpoints are intentionally unauthenticated and public (e.g. public search) — only flag rate-limit absence on genuinely sensitive/abusable endpoints.
- `app.set("trust proxy", true)` without a real proxy in front of the app lets a client spoof `req.ip` via `X-Forwarded-For`, making an IP-keyed limiter there ineffective — check the trust-proxy config before crediting an IP limiter as a real control.

## Safe patterns
```js
const ipLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, keyGenerator: (req) => req.ip });
const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => String(req.body.email ?? "").toLowerCase(),
});
app.post("/login", ipLimiter, emailLimiter, loginHandler);
```

## Fix guidance
Add per-account and per-IP rate limiting (or account lockout with backoff) to login, password reset, OTP verification, and coupon/invite lookup endpoints, using the framework's rate-limiting middleware or a shared store (Redis) so it works across instances. Combine with CAPTCHA after repeated failures for extra resilience.

## Severity guide
- Impact `high`: unlimited attempts allow full credential brute force or OTP bypass leading to account takeover.
- Impact `medium`: unlimited attempts allow enumeration (valid emails/usernames) or coupon/code guessing without full takeover.
- Impact `low`: limited-consequence abuse (e.g. minor resource use) with no security impact.
- Exploitability: `medium` by default since edge/WAF limits may exist outside the repo and cannot be confirmed; use `high` only when the repo/infra config confirms no limiting layer exists anywhere in the path.
