# Idempotency / Double-Spend
CWE-837 · OWASP A04:2021 · ASVS V11.1.6

## What it is
An operation with real-world side effects (charging a card, sending funds, granting a reward, issuing a coupon) can be triggered more than once for what the client intends as a single action — via network retries, double-clicks, or duplicate webhook/callback delivery — because the endpoint has no idempotency key or de-duplication check.

OWASP Top 10 2021 does not map CWE-837 to a category; A04 Insecure Design is the closest fit.

Concurrent duplicates hitting a check-then-act are `race-condition`; this class covers missing de-duplication of sequential retries and redeliveries. Webhook event-id replay is reported here, not in `webhook-signature`.

## Where to look
- Payment/checkout endpoints: `POST /charge`, `POST /orders`, `POST /payouts`, without accepting or storing an `Idempotency-Key`.
- Webhook/callback handlers (payment provider, queue consumer) that process an event without recording the event id as already-processed.
- "Claim reward"/"redeem" endpoints triggered by client retry logic (mobile clients retrying on timeout) with no dedup.
- Message queue consumers with at-least-once delivery semantics and no consumer-side dedup table.
- Client-side retry/backoff logic paired with a server endpoint that isn't safe to call twice.

## How to confirm
Check whether the endpoint accepts a client-supplied idempotency key (or derives one, e.g. from the webhook provider's event id) and persists it — with a unique constraint — before performing the side effect, or performs the side effect as an atomic conditional update ("charge only if not already charged"). Report when retrying the same logical request (same key/event id) would perform the side effect again.

## False-positive traps
- Payment providers (Stripe, etc.) support idempotency keys but only if the *client code* actually passes one — check the outgoing call, not just that the provider supports the feature.
- Read-only or naturally idempotent operations (PUT that fully replaces a resource, GET) don't need this.
- A queue consumer with exactly-once delivery guarantees from the broker (with correct configuration) may not need application-level dedup — verify the broker config actually guarantees this rather than assuming.
- A unique constraint on the resulting record (e.g. one order per cart checkout session) that causes retries to fail loudly and be handled by the client is a valid mitigation, not a false positive to ignore — but confirm the failure is actually handled, not swallowed.

## Safe patterns
```js
app.post("/charge", async (req, res) => {
  const key = req.headers["idempotency-key"];
  try {
    await db.idempotencyKeys.insertOne({ key, status: "processing" }); // unique index on key
  } catch (e) {
    if (e.code === DUPLICATE_KEY) {
      const existing = await db.idempotencyKeys.findOne({ key });
      return res.json(existing.result);
    }
    throw e;
  }
  const charge = await paymentProvider.charge({ ...req.body, idempotencyKey: key });
  await db.idempotencyKeys.updateOne({ key }, { $set: { status: "done", result: charge } });
  res.json(charge);
});
```

## Fix guidance
Require and store a client- or event-supplied idempotency key with a unique database constraint before performing the side effect, or make the effect itself an atomic conditional operation. For webhooks, record the provider's event id and skip already-seen events before processing.

## Severity guide
- Impact `high`: duplicate processing causes direct financial loss (double charge refund, double payout, duplicate fund transfer).
- Impact `medium`: duplicate processing causes non-financial but meaningful business-logic corruption (duplicate orders, doubled rewards/coupons).
- Impact `low`: harmless duplicate records with no business impact.
- Exploitability: `high` when the client can trigger the duplicate simply by retrying/resending a request itself; `medium` when it depends on provider-side retry behavior the attacker doesn't fully control.
