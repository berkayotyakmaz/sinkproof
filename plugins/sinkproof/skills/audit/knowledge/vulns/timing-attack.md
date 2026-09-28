# Timing Attack on Secret Comparison
CWE-208 · OWASP A02:2021 · ASVS V6.2.8

OWASP Top 10 2021 does not map CWE-208 to a category; A02 Cryptographic Failures is the closest fit.

## What it is
A secret value (password, token, API key, HMAC signature, session id) is compared to user input using a comparison that returns early on the first mismatched byte, so the time the comparison takes leaks how many leading bytes were correct, letting an attacker recover the secret byte-by-byte over many requests.

## Where to look
- Any `==`, `===`, `.equals()`, `strcmp`, `string ==`, or `memcmp`-style comparison applied to: API keys, webhook signatures (HMAC), password reset tokens, session/CSRF tokens, "remember me" tokens — anywhere a secret is checked against attacker-supplied input.
- Node: raw `===` on tokens instead of `crypto.timingSafeEqual`.
- Python: `==` on tokens instead of `hmac.compare_digest`.
- PHP: `==`/`===` instead of `hash_equals`.
- Java: `String.equals` instead of `MessageDigest.isEqual`.
- Go: `bytes.Equal`/`==` instead of `subtle.ConstantTimeCompare`.
- Note: bcrypt/argon2/scrypt password *verification* functions are already constant-time by design — this finding is about raw secret/token comparisons, not password hash verification.

## How to confirm
Show the specific comparison used on a secret that both (a) is compared against attacker-controlled input in a network-reachable code path, and (b) is high-value enough that a byte-at-a-time timing attack is worth the (often thousands of) requests it requires — e.g. HMAC webhook signature checks, API key checks. Distinguish this from a mere lint-style pattern match.

## False-positive traps
- Comparing two values neither of which is attacker-controlled (e.g. comparing two server-generated hashes) is not exploitable.
- Values compared over a network with highly variable latency (public internet, load-balanced/shared infrastructure) make the attack far harder in practice — still worth reporting, but at reduced exploitability, not dismissed.
- Password *login* checks already going through bcrypt/argon2/scrypt `compare`/`verify` functions are safe; only the token/signature-comparison variant applies here.
- Comparing short, low-entropy values (a 4-digit code with independent rate limiting) has a different, more direct brute-force risk — note it, but the primary issue is missing rate limiting, not timing.

## Safe patterns
```js
const crypto = require("crypto");
function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}
```

## Fix guidance
Use the platform's constant-time comparison for any secret-vs-attacker-input check: `crypto.timingSafeEqual` (Node), `hmac.compare_digest` (Python), `hash_equals` (PHP), `MessageDigest.isEqual` (Java), `subtle.ConstantTimeCompare` (Go). For HMAC signature verification, compare the computed HMAC to the provided one this way, and also rate-limit the endpoint.

## Severity guide
- Impact `high`: constant-time bypass would allow recovery of a high-value secret (API key, webhook signing secret, session token) granting significant access.
- Impact `medium`: recoverable secret has limited scope or short lifetime, reducing what an attacker gains.
- Impact `low`: comparison is on a low-value or already rate-limited value where recovery has minimal impact.
- Exploitability: `low` — requires sending a very large number of precisely timed requests, typically over a network with enough latency variance to make this impractical without a favorable network position.
