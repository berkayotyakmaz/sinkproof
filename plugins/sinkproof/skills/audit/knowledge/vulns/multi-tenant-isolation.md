# Multi-Tenant Isolation Failure
CWE-668 · OWASP A01:2021 · ASVS V4.2.1

## What it is
A system serving multiple tenants (organizations, workspaces, accounts) fails to scope a query, cache key, file path, or background job to the caller's tenant, letting one tenant read or modify another tenant's data. This is IDOR at the tenant boundary rather than the record boundary — it often affects entire tables or shared infrastructure, not just one row.

## Where to look
- ORM queries and raw SQL missing a `tenant_id`/`org_id`/`workspace_id` filter, especially in reports, search, exports, and admin/support tooling.
- Shared caches and queues keyed only by a resource id (Redis keys, job payloads) without a tenant prefix.
- File/object storage paths built without a tenant segment (`/uploads/{file_id}` instead of `/uploads/{tenant_id}/{file_id}`).
- Background jobs, cron tasks, and webhooks that load records by id without re-deriving and checking tenant context.
- Django/Rails/Laravel: default-manager querysets that aren't wrapped by a tenant-scoping middleware (e.g. `django-tenant-schemas`, Rails `default_scope`, Laravel global scopes) — check whether the scope is actually applied on the specific query.
- Postgres row-level security (RLS) policies that exist but are bypassed by a connection using a superuser/service role.

If one record id crosses tenants, report `idor`; use this class when a whole query, cache, storage path, or background job is missing the tenant scope entirely.

## How to confirm
Trace how the tenant identifier is established (session, JWT claim, subdomain) and follow it into the query/cache/storage layer. Report when a query, cache key, or file path can be reached with a valid session for tenant A but returns or writes data belonging to tenant B, because no tenant condition exists at any layer (query, middleware, RLS, storage prefix).

## False-positive traps
- A global ORM scope or RLS policy applied at the connection/session level may make an unscoped-looking query safe — verify it is actually active for that code path (some raw/bypass queries skip ORM scopes).
- Cross-tenant admin/support tools are intentionally unscoped for staff roles — confirm the caller's role, not just the query shape.
- Shared, intentionally public reference data (plans, templates) is not a tenant boundary.
- Physical separation (separate DB per tenant) still needs the connection-routing logic checked — a bug there is the same class of bug.

## Safe patterns
```python
class TenantQuerySet(models.QuerySet):
    def for_request(self, request):
        return self.filter(tenant_id=request.tenant.id)

invoices = Invoice.objects.for_request(request).get(pk=invoice_id)
```

## Fix guidance
Enforce tenant scoping at the lowest common layer possible — RLS or a mandatory query wrapper — so individual handlers cannot forget it. Prefix cache keys, storage paths, and job payloads with the tenant id, and re-validate tenant context inside background jobs rather than trusting the enqueueing caller.

## Severity guide
- Impact `high`: one tenant can read or modify another tenant's sensitive data (customers, billing, credentials) at scale.
- Impact `medium`: limited cross-tenant metadata exposure or a write limited to non-sensitive fields.
- Impact `low`: cross-tenant leak of non-sensitive, low-value data.
- Exploitability: `high` when any authenticated tenant user can trigger it through normal API use; `medium` when it requires knowledge of another tenant's identifiers or a specific feature path.
