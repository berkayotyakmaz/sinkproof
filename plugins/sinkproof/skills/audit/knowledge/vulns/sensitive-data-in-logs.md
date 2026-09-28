# Sensitive Data in Logs
CWE-532 · OWASP A09:2021 · ASVS V7.1.1

## What it is
Passwords, tokens, full payment card numbers, or other personal/sensitive data are written to application logs, crash reports, analytics events, or returned in error responses, where they are readable by anyone with log or error-tracking access — a broader and less controlled audience than the data's normal access path.

## Where to look
- Request/response logging middleware that logs full bodies or headers (`Authorization`, `Cookie`, `X-Api-Key`) without redaction.
- `console.log`/`logger.info`/`print`/`System.out.println` calls on entire request objects, user objects, or exception objects during login, registration, password reset, or payment flows.
- Error handlers that serialize the full exception (including request context) into the log or into an HTTP error response body (stack traces, SQL with bound values, raw request payloads).
- Third-party crash/analytics SDKs (Sentry, Datadog, New Relic, Bugsnag) configured to capture full request bodies or user PII by default.
- Structured logging calls (`logger.info("login", { email, password })`) that include a field literally named `password`, `token`, `ssn`, `cardNumber`, `cvv`.

## How to confirm
Show the specific log/error statement and that a sensitive field (credential, token, full card number, national ID, health data) flows into it unredacted, and identify who can read that sink (log aggregator, APM dashboard, client-visible error response) versus who should be able to see that data.

## False-positive traps
- Logging a user id, masked/last-4 card digits, redacted token prefix (`tok_***abcd`), or hashed identifier is the recommended pattern, not a finding.
- Debug-level logs gated behind a flag that is confirmed disabled in production are lower priority than logs that always run — check the environment/build config, don't assume.
- Logging that an authentication attempt failed (without the password itself) is normal and desired security logging — don't flag the event, only the sensitive payload attached to it.
- A field name containing "token" that holds a non-secret, short-lived, single-use CSRF or pagination token has much lower impact than a session/auth token — read what the value actually is before rating severity.
- This is distinct from log injection (attacker-controlled data forging log entries via newlines/ANSI codes) — that belongs in a separate `log-injection` finding, not here.

## Safe patterns
```js
function safeLogFields(body) {
  const { password, token, cardNumber, ...rest } = body;
  return rest; // never pass the original body to the logger
}
logger.info("checkout attempt", safeLogFields(req.body));
```

## Fix guidance
Redact or omit known-sensitive fields before logging (deny-list common names: password, token, secret, authorization, ssn, cardNumber, cvv); mask card numbers to last four digits per PCI DSS; strip `Authorization`/`Cookie` headers in request-logging middleware; return generic error messages to clients while logging detail server-side only; configure APM/crash-reporting SDKs to scrub PII before upload; review log retention and access controls.

## Severity guide
- Impact `high`: plaintext passwords, full payment card numbers, or authentication tokens written to logs or returned in error responses, reachable by broad internal or third-party access.
- Impact `medium`: other personal data (email, address, partial identifiers) logged without redaction, or sensitive data logged but restricted to a small, access-controlled log store.
- Impact `low`: low-sensitivity metadata logged that offers minor information leakage.
- Exploitability: `medium` — requires access to the log store, error-tracking dashboard, or a client-visible error response; treat as `high` if that log access is already broadly shared (e.g. third-party SaaS logging with many employee accounts) or if the data appears directly in a client-facing error response.
