# Missing or Weak Webhook Signature Verification
CWE-345 · OWASP A08:2021 · ASVS V13.2.6

## What it is
An endpoint that receives webhooks/callbacks from an external provider (payment processor, SaaS integration) processes the payload without verifying it was genuinely sent by that provider, or the verification is implemented incorrectly (wrong hash comparison, no raw-body check, no replay protection), letting an attacker forge events directly.

## Where to look
- Webhook receiver routes: `/webhooks/stripe`, `/callbacks/*`, `/hooks/*` — check for a signature-verification call using the provider's SDK (`stripe.webhooks.constructEvent`, GitHub's `X-Hub-Signature-256`, etc.) before the payload is trusted.
- Body parsing: does the framework's body parser run *before* signature verification and re-serialize/mutate the JSON? Signature verification needs the exact raw bytes provider signed — parsing then re-stringifying breaks it.
- Comparison logic: manual HMAC comparisons using `==`/`string.Equals` instead of a constant-time comparison (`crypto.timingSafeEqual`, `hmac.compare_digest`).
- Timestamp handling: does the handler check a signed timestamp header against a tolerance window (e.g. 5 minutes) to reject old, replayed payloads?
- Replay protection: is the provider's event id recorded and checked so the same valid, signed event can't be reprocessed?

## How to confirm
Find the raw body used for signature computation (must be pre-parsing, unmodified bytes) and confirm the handler recomputes the HMAC/signature from the shared secret and compares it to the header using a constant-time function, before using any field from the payload. Report when signature verification is missing entirely, computed against a re-serialized/parsed body instead of the raw bytes, uses a non-constant-time comparison, or has no timestamp/replay check.

## False-positive traps
- Some frameworks expose both a raw-body buffer and a parsed body on the same request (Express with `express.raw()` on that specific route, or a raw-body middleware placed before `express.json()`) — check that the *raw* buffer is what's actually passed to the verify function, not that raw-body access exists somewhere in the codebase.
- Provider SDK helper functions (`stripe.webhooks.constructEvent`) already do constant-time comparison and timestamp checks internally — using them correctly (with the right raw body and secret) is sufficient; don't require hand-rolled checks on top.
- IP allow-listing the provider's known IPs is a defense-in-depth layer, not a substitute for signature verification — don't treat its presence as clearing the finding.
- A webhook secret rotated per environment and stored in a secrets manager, correctly loaded, is fine even if the code also has a fallback for local dev testing — check the fallback isn't reachable in production.
- Some providers (e.g. GitHub) sign the payload but not a timestamp — a missing timestamp/tolerance check is not a finding for those providers; only flag it when the provider actually issues a signed timestamp that the handler ignores.

A non-constant-time comparison in webhook signature verification is reported here only; do not also file it as `timing-attack`.

## Safe patterns
```js
app.post(
  "/webhooks/stripe",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const event = stripe.webhooks.constructEvent(
      req.body, // raw Buffer
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    ); // throws on bad signature, stale timestamp, or replay outside tolerance
    ...
  }
);
```

## Fix guidance
Verify signatures against the untouched raw request body using the provider's SDK where available, with a constant-time comparison if implemented manually. Reject requests whose signed timestamp is outside a small tolerance window, and record processed event ids to reject replays of otherwise-valid signed events.

## Severity guide
- Impact `high`: forged webhooks can trigger financial actions (mark order paid, issue refund, grant access) without a real event from the provider.
- Impact `medium`: forged webhooks cause data integrity issues or trigger non-financial but consequential actions.
- Impact `low`: forged webhooks only affect logging/analytics with no functional impact.
- Exploitability: `high` when signature verification is entirely absent (anyone can POST a payload); `medium` when verification exists but a specific weakness (timing attack, replay) is needed to exploit it.
