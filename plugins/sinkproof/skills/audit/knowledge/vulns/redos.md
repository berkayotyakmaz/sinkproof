# Regular Expression Denial of Service (ReDoS)
CWE-1333 · OWASP A05:2021 · ASVS V5.1.3

OWASP Top 10 2021 does not map CWE-1333 to a category; A05 Security Misconfiguration is the closest fit. ASVS 4.0.3 has no ReDoS requirement; V5.1.3 (input validation) is the closest fit.

## What it is
A regular expression's structure causes catastrophic backtracking on certain inputs, so matching time grows exponentially with input length; an attacker who controls the matched string (or the pattern itself) can hang a worker thread or the whole process.

## Where to look
- Sinks: any `RegExp`/`re.compile`/`preg_match`/`Regexp.new` applied to untrusted input — request bodies, headers, form fields, filenames — especially in validation (email/URL/path format checks), routing, or log-scanning code.
- Risky shapes to describe in review, in words rather than crafted examples: a quantified group that itself contains a quantified sub-pattern (nesting, e.g. "one-or-more of (one-or-more of X)"); two adjacent quantified patterns that can both match overlapping substrings of the input (e.g. "digits-or-letters repeated" followed by "digits repeated"); alternation inside a repeated group where the alternatives overlap in what they can match.
- Also flag regexes built dynamically from user input (the pattern itself, not just the subject string, is attacker-controlled).

## How to confirm
Identify the specific nested-or-overlapping-quantifier shape in the pattern, show that the matched subject string comes from untrusted input, and note there is no length cap, timeout, or safe-regex engine (RE2) applied before matching.

## False-positive traps
- Patterns with no nested or overlapping quantifiers (a single flat sequence of literals and simple classes) are not vulnerable to catastrophic backtracking regardless of input length.
- Engines that guarantee linear-time matching (RE2, Go's `regexp`, Rust's `regex` crate) are not susceptible to this class of backtracking blowup even with a risky-looking pattern.
- A hard input-length cap applied before the regex runs (e.g. reject inputs over a few hundred characters) bounds worst-case time to something acceptable even for a risky pattern.
- A regex-matching call wrapped in an enforced timeout that aborts long-running matches mitigates the impact even if the pattern itself is risky.

## Safe patterns
```js
// Flat, non-nested pattern with a length guard before matching
if (input.length > 254) throw new Error("too long");
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
EMAIL.test(input);
```

## Fix guidance
Rewrite nested/overlapping-quantifier patterns to a flatter equivalent, cap input length before matching, run a linter such as `safe-regex`/`eslint-plugin-redos` in CI, or switch the matching engine to RE2 (or an engine with a built-in matching timeout) for patterns applied to untrusted input.

## Severity guide
- Impact `high`: a single request can hang the main thread or exhaust a shared worker pool, taking down the service for all users.
- Impact `medium`: denial of service limited to one request/connection or a non-critical background worker.
- Impact `low`: measurable slowdown but bounded by an existing length cap or timeout.
- Exploitability: `high` when unauthenticated or ordinary users control the matched string; `medium` when a specific role is needed; `low` for admin-only input.
