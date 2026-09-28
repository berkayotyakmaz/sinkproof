# Broken Function-Level Authorization
CWE-862 · OWASP A01:2021 · ASVS V4.1.3

## What it is
An endpoint or action performs a sensitive operation (admin action, internal API, elevated feature) without checking that the caller's role or permission actually allows it. Unlike IDOR, the bug is not about which record is targeted but whether the *function itself* should be reachable by this user at all.

## Where to look
- Admin/internal routes: `/admin/*`, `/internal/*`, background-job triggers, feature-flag toggles, user-role changes, refund/void endpoints.
- Node/Express: routes mounted without an `isAdmin`/`requireRole` middleware; Next.js API routes and Server Actions with no session-role check.
- Django/Flask/FastAPI: views missing `@staff_member_required`, `@permission_required`, or a dependency that checks `current_user.role`.
- Laravel/Rails: controllers not covered by a `Gate`/`Policy` (`authorize`) or `before_action` role filter.
- Spring: `@PreAuthorize`/`@Secured` missing on a controller method that mutates state.
- GraphQL: mutations/resolvers with no per-field authorization, only object-level checks.
- Frontend client-side route tables: Angular `*.routing.ts` (`canActivate`, `canMatch`), React Router `routes.tsx`, Vue `router/index.ts`, Next.js `app/**/page.tsx`. Look for admin or internal pages that exist but are unlinked or only hidden in the UI, and for guards that check a client-side flag. A client-side guard is never the control: confirm the API endpoints those pages call enforce the role on the server. If they do, report the hidden route at impact `low` (information disclosure); if they do not, report the server endpoint.

## How to confirm
Find the route/handler, then check whether any layer on the path enforces a role/permission: middleware, decorator, policy object, framework-level RBAC config (e.g. Spring Security filter chain, Laravel route groups). If the same action is reachable through a UI that hides the button but the backend route has no server-side check, it is exploitable directly.

## False-positive traps
- The check can live in shared middleware, a route group, or a framework's central authorization config rather than in the handler itself — read the full route registration before reporting.
- Frameworks that default-deny (e.g. Spring Security with `anyRequest().authenticated()` plus explicit role rules) may cover the route even without a local annotation.
- An endpoint only reachable via an internal network/service mesh with no public ingress is lower exploitability, not a false positive — still report but note the constraint.
- A route behind a shared "logged in" check is not the same as a role check — confirm it verifies the *specific* privilege, not just authentication.

## Safe patterns
```python
@router.post("/admin/users/{user_id}/ban")
def ban_user(user_id: int, current_user: User = Depends(require_role("admin"))):
    ...
```

## Fix guidance
Enforce role/permission checks centrally (middleware, route guards, or a policy/RBAC layer) rather than per-handler, so new endpoints inherit protection by default. Deny by default and allow-list privileged routes explicitly. Add a test that hits every privileged route as a low-privilege user and expects 403.

## Severity guide
- Impact `high`: unauthenticated or low-privilege user can perform admin actions, change roles, or access other tenants' data via the function.
- Impact `medium`: the function affects only the caller's own data but performs an action the UI does not expose, or requires an authenticated but low-privilege account.
- Impact `low`: the function exposes non-sensitive internal information.
- Exploitability: `high` when any logged-in user can call the route directly; `medium` when a specific low-privilege role is required first.
