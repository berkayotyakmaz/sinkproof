# Weak Password Hashing
CWE-916 · OWASP A02:2021 · ASVS V2.4.1

## What it is
User passwords are stored using a fast general-purpose hash (or no hash at all) instead of a slow, memory-hard algorithm designed for password storage, so a stolen database can be cracked by offline brute force at high speed.

## Where to look
- Node: `crypto.createHash("md5"/"sha1"/"sha256")` applied directly to a password, home-grown salting, or absence of `bcrypt`/`argon2`/`scrypt` libraries in the auth flow.
- Python: `hashlib.md5`/`sha256` on a password, Django `PASSWORD_HASHERS` set to a weak hasher, or password checked with plain `==`.
- PHP: `md5($password)`, `sha1($password)` instead of `password_hash()`/`password_verify()`.
- Ruby/Rails: custom `Digest::SHA256` on passwords instead of `has_secure_password` (bcrypt).
- Java/Spring: `MessageDigest.getInstance("SHA-256")` used for passwords instead of `BCryptPasswordEncoder`/`Argon2PasswordEncoder`.
- Go: `sha256.Sum256` on a password instead of `golang.org/x/crypto/bcrypt`.
- Also flag: passwords encrypted (reversible) instead of hashed, hard-coded/missing salt, low work factor (`bcrypt` cost < 10, low `argon2`/`pbkdf2` iteration counts).

## How to confirm
Show the exact hashing call used on the password at registration/reset and at login verification. Confirm it is a fast general-purpose digest (MD5, SHA-1, SHA-256/512 alone) rather than bcrypt/scrypt/argon2/PBKDF2 with an adequate work factor, or that passwords are stored in plaintext/reversibly encrypted.

## False-positive traps
- The same fast hash used for non-password purposes (file checksums, cache keys, ETags, HMAC signatures with a secret key) is not this finding.
- A framework's default password hasher (Django's PBKDF2, Rails `has_secure_password`'s bcrypt, Spring Security's `BCryptPasswordEncoder`) is safe unless explicitly overridden with a weaker one.
- PBKDF2 with a high iteration count (current OWASP guidance) is an acceptable password hash, not automatically weak — check the iteration count before flagging.
- Hashing used for API keys/tokens that are high-entropy and randomly generated (not user-chosen passwords) has different guidance; a fast hash there is a lower-priority finding, not this one.

## Safe patterns
```js
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(password, 12);
const ok = await bcrypt.compare(candidate, storedHash);
```

## Fix guidance
Use bcrypt, scrypt, or argon2id with parameters meeting current OWASP recommendations; migrate existing users by re-hashing on next successful login; never encrypt passwords reversibly; always use a unique per-password salt (these libraries handle it automatically); enforce a minimum work factor in code review/CI.

## Severity guide
- Impact `high`: fast hash, salted or not (or plaintext) protecting production user credentials for an authentication system with real accounts.
- Impact `medium`: a slow algorithm used but with an inadequate work factor, or weak hashing on a lower-value credential store (internal tool, staging).
- Impact `low`: weak hashing found in test fixtures, seed scripts, or non-production tooling that never touches real user passwords.
- Exploitability: `medium` — the attacker first needs the password database (via another breach or injection); once obtained, cracking is offline and unlimited, so treat it as `high` if database exposure is already a confirmed finding elsewhere.
