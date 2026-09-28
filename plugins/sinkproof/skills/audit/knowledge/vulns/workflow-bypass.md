# Workflow / State-Machine Bypass
CWE-841 · OWASP A04:2021 · ASVS V11.1.1

## What it is
A multi-step process (checkout, KYC/verification, approval flow, order fulfillment) enforces its intended sequence only in the client UI, not in the backend. A request that jumps straight to a later step, replays an earlier one, or skips a required state transition is accepted anyway, because the server doesn't verify the current state before advancing it.

## Where to look
- Multi-step checkout/onboarding: endpoints for step 3 (e.g. "confirm order") that don't check the record is actually in the step 2 ("payment authorized") state first.
- Approval workflows: status transitions (`draft → submitted → approved → paid`) applied by directly setting a status field from client input, rather than validating the transition against the current state.
- State stored only in client-side session/local storage or hidden form fields, with the server trusting whatever "current step" the client claims.
- Order/fulfillment systems where "ship"/"refund" actions don't check that "paid"/"confirmed" actually happened first.
- Look for a status/state enum field updated via a generic `PATCH`/`update` endpoint that accepts any value rather than a dedicated transition endpoint with guard checks.

## How to confirm
Map the intended state machine (from tests, docs, or UI flow) and check each transition endpoint for a guard: does it read the record's current state and reject the request if the precondition state isn't met? Report when a later-step endpoint can be called while the record is still in an earlier state. A status field set through a generic `PATCH` of the request body (any field, any value) is `mass-assignment`; use `workflow-bypass` when a dedicated step/transition endpoint can be called out of order instead.

## False-positive traps
- A frontend that disables buttons for "future" steps is not a backend guard — always verify server-side enforcement independently of UI state.
- Idempotent re-submission of the *same* completed step (e.g. re-confirming an already-confirmed order, returning the existing result) is often intentional and safe — the bug is skipping *ahead*, not repeating.
- Admin/support tooling that intentionally allows manual state overrides for a privileged role is not a bypass if properly gated by role checks.
- A state machine library (e.g. Rails AASM, `xstate`, Spring Statemachine) enforces valid transitions automatically when used correctly — check that the transition call goes through the library's guarded API, not a raw field assignment that bypasses it.

## Safe patterns
```python
def confirm_order(order_id, user):
    with transaction.atomic():
        order = Order.objects.select_for_update().get(pk=order_id, user=user)
        if order.status != "payment_authorized":
            raise InvalidTransition(order.status, "confirmed")
        order.status = "confirmed"
        order.save()
```

## Fix guidance
Validate the current state before applying any transition, ideally through a state machine library or a small set of dedicated transition functions rather than a generic field-update endpoint. Store authoritative state server-side only, never trust a client-supplied "current step."

## Severity guide
- Impact `high`: skipping a step bypasses payment, identity verification, or an approval required before a high-value action.
- Impact `medium`: skipping a step causes data integrity problems or unauthorized but lower-value actions.
- Impact `low`: skipping a step has cosmetic or minor workflow impact.
- Exploitability: `high` when any authenticated user can call the later-step endpoint directly with no special conditions; `medium` when it requires specific timing or partial completion of prior steps.
