# IDOR (Insecure Direct Object Reference)
CWE-639 · OWASP A01:2021 · ASVS V4.2.1

## What it is
A handler reads or changes a record using an identifier taken from the request, without checking that the current user is allowed to access that specific record.

## Where to look
- Sources: route params (`/orders/:id`), query strings, body fields named `id`, `*Id`, `*_id`, `uuid`, hidden form fields, GraphQL arguments, ids inside arrays for bulk endpoints.
- Sinks: `findById`, `findByPk`, `get(pk=…)`, `SELECT … WHERE id = ?`, update/delete by id, file or object-storage keys built from ids.
- Hot spots: downloads and exports, invoices, messages, attachments, "share" links, mobile API endpoints, bulk endpoints.

## How to confirm
Trace the id from source to sink and list every check on the path. Report only when nothing ties the record to the caller: no owner/tenant condition in the query, no scoped lookup through the user (`user.orders.find(id)`), no policy or `authorize()` call, no route middleware or decorator that performs the check.

## False-positive traps
- Scoped queries are checks: `current_user.orders.find(id)`, `Order.objects.filter(user=request.user).get(pk=id)`.
- The check may live elsewhere: route middleware, decorators (`@permission_required`), policy classes, Postgres row-level security. Read them before reporting.
- Unguessable ids (UUIDv4) do not make it safe — ids leak through URLs, logs and shared links. Still report, with exploitability `medium`.
- Intentionally public resources (published posts, public profiles) are not IDOR.

## Safe patterns
```js
const order = await db.query(
  "SELECT * FROM orders WHERE id = ? AND user_id = ?",
  [req.params.id, req.user.id]
);
if (!order) return res.sendStatus(404);
```

## Fix guidance
Scope the lookup by owner or tenant in the same query, or call one central authorization policy before returning or changing the record. Return 404 rather than 403 so existence is not confirmed.

## Severity guide
- Impact `high`: other users' sensitive data (PII, payments, messages) can be read or changed.
- Impact `medium`: less sensitive data, or write access to non-sensitive records.
- Impact `low`: low-sensitivity data only.
- Exploitability: `high` for sequential or guessable ids reachable by any logged-in user; `medium` when the id must leak first (UUIDs) or a specific role is needed.
