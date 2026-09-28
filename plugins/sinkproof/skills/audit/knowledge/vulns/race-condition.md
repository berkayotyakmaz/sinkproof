# Race Condition (check-then-act)
CWE-362 · OWASP A04:2021 · ASVS V11.1.6

## What it is
The code reads state, decides, then writes in separate steps. Two concurrent requests both pass the check before either writes, so a limit is broken: a coupon used twice, a balance spent twice, a unique name taken twice.

OWASP Top 10 2021 does not map CWE-362 to a category; A04 Insecure Design is the closest fit and is used here.

## Where to look
- Money and limits: balance, credits, stock, coupons, gift cards, votes, invites, quotas, free trials.
- Pattern: `SELECT` / `find` → `if` → `UPDATE` / `save` with no transaction plus row lock, no atomic conditional update and no unique constraint.
- Also: in-memory counters or caches in multi-process servers, "get or create" without a unique index.

## How to confirm
Show the read, the decision and the write, and show that none of these protect them: a transaction with `SELECT … FOR UPDATE` or serializable isolation, an atomic conditional write (`UPDATE … SET used = true WHERE id = ? AND used = false` with the affected row count checked), a unique constraint the write relies on, or a distributed lock.

## False-positive traps
- A transaction alone at the default isolation level (READ COMMITTED) does not stop this; it must lock the row or use a conditional write.
- A unique index makes a duplicate insert fail — check that the code handles that failure.
- Single-threaded runtimes (Node.js) still race whenever there is an `await` between the check and the write.

## Safe patterns
```js
const result = await db.query(
  "UPDATE coupons SET redeemed_by = ? WHERE code = ? AND redeemed_by IS NULL",
  [req.user.id, code]
);
if (result.affectedRows === 0) return res.status(409).send("Already redeemed");
```

## Fix guidance
Make the check and the write one atomic operation (conditional update, row lock inside a transaction, or a unique constraint), and handle the "lost" case explicitly. Add an idempotency key for payment-like operations.

## Severity guide
- Impact `high`: direct financial loss (double spend, double withdrawal, unlimited credits).
- Impact `medium`: bypass of business limits (coupons, trials, stock) or duplicates that break data integrity.
- Impact `low`: harmless duplicates.
- Exploitability: `high` when the user can trigger the race by sending parallel requests themselves (the usual case when there is an `await` or a round trip between check and write); `medium` when the window depends on timing the attacker cannot control.
