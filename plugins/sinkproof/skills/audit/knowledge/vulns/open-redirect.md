# Open Redirect
CWE-601 · OWASP A01:2021 · ASVS V5.1.5

## What it is
The application (or client-side code) sends a user to a URL taken from user input — a query parameter, form field, or header — without checking that the destination stays on the same site, letting an attacker craft a link through a trusted domain to an arbitrary destination.

## Where to look
- Server sinks: `res.redirect(req.query.returnUrl)`, `redirect_to(params[:next])` (Rails), `return redirect(request.args.get("next"))` (Flask), `RedirectResponse` / `Response.sendRedirect` (Java/Spring, Servlet), `header("Location: " . $_GET['url'])` (PHP), HTTP 3xx `Location` headers built from input.
- Client sinks: `window.location = returnUrl`, `location.href = next`, `history.push(returnUrl)` / router `push`/`replace` fed from a `returnUrl`, `next`, `redirect`, or `continue` query parameter, often after login or logout flows.
- Sources: `returnUrl`, `next`, `redirect`, `continue`, `dest`, `callback` query/body parameters; OAuth `redirect_uri`.

## How to confirm
Trace the parameter from the request into the redirect sink and show there is no same-origin/path check, or that the check only inspects a prefix (`startsWith("/")` without also rejecting `//` or `/\`) or a substring (`.includes("example.com")`), which an attacker-controlled domain can satisfy. If the destination can carry a non-`http(s)` scheme (`javascript:`, `data:`), treat it as script execution reachable via a redirect — cross-reference `xss` instead of, or in addition to, open redirect.

## False-positive traps
- A redirect target validated against an allow-list of full origins, or restricted to a relative path with `//` and backslash rejected, is safe.
- Frameworks that resolve relative redirects safely by default (e.g. Rails `redirect_to` combined with `only_path: true`, or an internal route name rather than a raw URL) are not vulnerable.
- A redirect to a value the server itself generated (not sourced from the request) is not open redirect.
- OAuth/OIDC flows that validate `redirect_uri` against a pre-registered list at the identity provider are protected even if the app also echoes the parameter.

## Safe patterns
```js
function safeRedirect(target) {
  if (typeof target !== "string" || !target.startsWith("/") || target.startsWith("//") || target.startsWith("/\\")) {
    return "/";
  }
  return target;
}
res.redirect(safeRedirect(req.query.returnUrl));
```

## Fix guidance
Prefer redirecting to a fixed set of named routes instead of an arbitrary URL. When a caller-supplied destination is required, restrict it to a same-origin relative path (reject absolute URLs, `//`, and backslash-prefixed paths) or validate the parsed hostname against an allow-list before redirecting, on both server and client.

## Severity guide
- Impact `high`: used as a step in a phishing or OAuth token theft chain, or the target can carry a non-`http(s)` scheme that executes script.
- Impact `medium`: redirects to an attacker-controlled site with no script execution, usable for phishing.
- Impact `low`: redirect target is constrained to a small set of external domains the site already trusts.
- Exploitability: `high` — a single crafted link works for any user who clicks it; no authentication required to trigger.
