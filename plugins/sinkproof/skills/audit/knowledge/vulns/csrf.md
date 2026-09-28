# CSRF (Cross-Site Request Forgery)
CWE-352 · OWASP A01:2021 · ASVS V4.2.2

## What it is
A state-changing endpoint relies solely on ambient credentials (a cookie sent automatically by the browser) to authenticate a request, with no per-request proof that the request was intentionally made by the user from the application's own origin. A malicious page can then trigger the action from a logged-in victim's browser.

## Where to look
- Any state-changing endpoint (POST/PUT/PATCH/DELETE) that authenticates purely via a session cookie: account changes, money transfers, email/password updates, admin actions.
- Express/Next.js: absence of `csurf`/`csrf-csrf` middleware or an equivalent custom token check on cookie-authenticated routes.
- Django: `@csrf_exempt` decorators, or `CSRF_COOKIE_*`/`CsrfViewMiddleware` disabled.
- Rails: `protect_from_forgery`/`skip_before_action :verify_authenticity_token`.
- Laravel: routes excluded from the `VerifyCsrfToken` middleware's `$except` list.
- Cookie config: `SameSite` attribute on the session cookie (`Strict`/`Lax` vs `None`) — this is the CSRF-relevant cookie flag; `HttpOnly`/`Secure` are covered by `session-management`.

## How to confirm
Identify how the request is authenticated. If it's cookie-based, check for a synchronizer token (hidden form field or header compared against a session-bound value) or double-submit cookie pattern, and check the cookie's `SameSite` setting. Report when a cookie-authenticated, state-changing endpoint has none of these and `SameSite` is `None` or unset in a way the browser treats permissively for the relevant request type.

## False-positive traps
- `SameSite=Lax` is the default only in Chromium-based browsers when no attribute is set; don't assume it as a universal default across all browsers/clients. Even where it applies, `Lax` still allows top-level cross-site GET navigations and does not stop an attacker on a same-site subdomain — it blocks cross-site POST from another site for most cases, but a missing explicit CSRF token on a `Lax`-cookied endpoint is still a weaker finding than on `SameSite=None`, not full protection; note this in severity.
- `csurf` is deprecated and unmaintained — its presence is not a strong signal of an actively maintained control; note this when it's the only CSRF mechanism in use and suggest a maintained alternative (e.g. `csrf-csrf`).
- APIs authenticated by a bearer token in a custom header (not a cookie), where the token is never auto-attached by the browser, are not CSRF-vulnerable — a cross-site page cannot read or set that header. Don't flag header-token-only APIs.
- Framework CSRF middleware enabled globally with a few explicitly and deliberately exempted webhook/API routes (which use their own signature verification) is a false positive — check what the exempted route actually authenticates with.
- GET requests that change state are a separate bug (should be idempotent) — don't conflate with CSRF, though report both.

## Safe patterns
```python
# Django: CsrfViewMiddleware enabled, template includes {% csrf_token %},
# and the view is NOT decorated @csrf_exempt.
@require_POST
def transfer_funds(request):
    form = TransferForm(request.POST)  # validated, includes csrfmiddlewaretoken
    ...
```

## Fix guidance
For cookie-authenticated apps, keep the framework's CSRF middleware enabled on all state-changing routes and set the session cookie `SameSite=Lax` or `Strict` as a defense-in-depth layer, not a replacement for tokens. For APIs, prefer bearer tokens in headers over cookies where practical; if cookies must be used for an API, implement double-submit or synchronizer tokens explicitly.

## Severity guide
- Impact `high`: forged requests can change account security settings, move funds, or take over the account.
- Impact `medium`: forged requests can perform other state changes (post content, change non-security settings).
- Impact `low`: forged requests trigger low-consequence actions.
- Exploitability: `high` when `SameSite` is `None`/absent and no token check exists, so any victim visiting an attacker page while logged in is affected; `medium` when `SameSite=Lax` provides partial mitigation or the action requires a rare request method browsers restrict.
