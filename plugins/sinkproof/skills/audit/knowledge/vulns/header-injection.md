# HTTP Header / CRLF Injection
CWE-113 · OWASP A03:2021 · ASVS V5.3.1

## What it is
Untrusted data containing carriage-return/line-feed characters reaches an HTTP response header without neutralization, letting an attacker inject additional headers, split the response, or (in older stacks) perform response-splitting cache poisoning.

## Where to look
- Sinks: `res.setHeader(name, userInput)`, `res.set(name, userInput)`, `res.redirect(userInput)`/`Location` built from user data, `header("X-Foo: " + input)` (PHP), `response.setHeader` (Java Servlet), `w.Header().Set(name, userInput)` (Go), `response['X-Foo'] = params[:x]` (Rails).
- Any header value assembled from request data: redirect targets, `Set-Cookie` values built manually, custom headers echoing a user-supplied filename or request ID.
- Also: log-forwarding or proxy code that copies a client-supplied header value verbatim into an outbound request header.

## How to confirm
Show untrusted input reaching a header-setting call with no rejection/stripping of CR/LF (or other header-breaking characters) before it, and that the underlying HTTP library does not already reject such input.

## False-positive traps
- Modern HTTP libraries (Node's `http`, Go's `net/http`, most current Java/Python web frameworks) already reject or throw on CR/LF in header values by default — check the library/runtime version before flagging.
- Header values built from fixed, developer-controlled strings with only a validated enum or numeric value interpolated are safe.
- `Set-Cookie` set via a dedicated cookie API (`res.cookie(name, value, opts)`) that encodes the value is safe; manual string-built `Set-Cookie` headers are not.
- A redirect target validated against an allow-list of paths or a same-origin check before being placed in `Location` is safe.
- Express's `res.redirect` URL-encodes CR/LF in the target before writing the `Location` header, so a raw newline in the input does not become a split header through that API.

## Safe patterns
```js
const allowed = new Set(["/", "/dashboard", "/settings"]);
const target = allowed.has(req.query.next) ? req.query.next : "/";
res.redirect(target);
```

## Fix guidance
Reject or strip CR/LF and other control characters from any value placed in a header; prefer framework APIs that encode automatically (`res.cookie`, `res.redirect` with an allow-listed target) over manual header string-building; validate redirect targets against an allow-list or same-origin check.

## Severity guide
- Impact `high`: enables session fixation or cache poisoning affecting other users. For an attacker-controlled redirect target itself, report `open-redirect` instead.
- Impact `medium`: header injection limited to the attacker's own response/session.
- Impact `low`: cosmetic header manipulation with no security consequence.
- Exploitability: `high` when unauthenticated or ordinary users control the value; `medium` when a specific role or victim interaction is needed; `low` for admin-only input.
