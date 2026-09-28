# Session Management Flaws
CWE-613 · OWASP A07:2021 · ASVS V3.3.1

## What it is
The application issues or maintains session identifiers (cookies, server-side sessions) in a way that lets a session be stolen, fixed, or kept alive after it should have ended — via missing expiration, session fixation, predictable ids, or no invalidation on logout/password change.

## Where to look
- Session creation: does login issue a *new* session id, or reuse the pre-login one (session fixation)?
- Cookie flags on the session cookie: `Secure`, `HttpOnly` — check the framework's session cookie config (Express `express-session` options, Django `SESSION_COOKIE_*` settings, Rails `session_store.rb`, Laravel `config/session.php`). These flags (session cookie confidentiality/JS access) belong here; `SameSite` as a CSRF control belongs to `csrf`.
- Expiration: absolute and idle timeouts server-side, not just client-side cookie `Max-Age`.
- Invalidation: does logout destroy the server-side session/token, or just clear the client cookie? Does password change or role change invalidate other active sessions?
- Session id generation: source of randomness (must be a CSPRNG), length, and whether it's predictable/sequential.
- Storage: session data in a shared store (Redis, DB) reachable across the whole app without tenant scoping.

## How to confirm
Walk the login → session-use → logout lifecycle in code: confirm a fresh, high-entropy session id is issued post-authentication, the store enforces both idle and absolute expiry, and logout/password-change actually removes the server-side record (not just the cookie). Report when any of these steps is missing and would let a session survive or be reused when it shouldn't.

## False-positive traps
- Framework session middleware often regenerates the session id on login automatically (e.g. Rails/Devise, Django's `login()` call) — verify the actual call path before flagging fixation. `express-session` does *not* regenerate the session id on login by itself — the app must call `req.session.regenerate()`. Passport 0.6+ does call session regeneration on `req.login()` by default — check the Passport version before flagging fixation on an app that relies on it.
- Stateless JWT-based "sessions" don't have server-side storage to invalidate; that's a JWT concern (see `jwt.md`), not a session-fixation finding, unless the app also claims a logout/revoke feature.
- Short session cookie `Max-Age` set client-side is a UX hint only — the real control is server-side expiry; check both.
- Multi-device login is often intentional; don't flag concurrent sessions as a bug unless the app claims single-session enforcement.

## Safe patterns
```js
app.post("/login", async (req, res) => {
  const user = await authenticate(req.body);
  req.session.regenerate((err) => {
    req.session.userId = user.id;
    req.session.cookie.maxAge = 30 * 60 * 1000;
    res.sendStatus(200);
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.clearCookie("connect.sid").sendStatus(200));
});
```

## Fix guidance
Regenerate the session id on authentication (login, privilege change), set `HttpOnly`, `Secure`, and an appropriate `SameSite` on the cookie, enforce both idle and absolute server-side expiry, and destroy the server-side session record on logout and on password/role change. Use the framework's CSPRNG-backed session id generation rather than a custom one.

## Severity guide
- Impact `high`: session fixation or missing invalidation lets an attacker gain or retain another user's authenticated session.
- Impact `medium`: sessions persist longer than they should (no idle/absolute timeout) but require an already-obtained cookie.
- Impact `low`: missing cookie hardening flags with no demonstrated session-theft path.
- Exploitability: `high` when fixation is reachable pre-authentication or logout doesn't invalidate server-side state; `medium` when it depends on network capture or a stolen cookie via another vector.
