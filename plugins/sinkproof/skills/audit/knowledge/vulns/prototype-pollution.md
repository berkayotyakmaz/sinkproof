# Prototype Pollution
CWE-1321 · OWASP A03:2021 · ASVS V5.1.2

OWASP Top 10 2021 does not map CWE-1321 to a category; A03 Injection is the closest fit. ASVS 4.0.3 has no prototype-pollution requirement; V5.1.2 (unsafe parameter assignment) is the closest fit.

## What it is
Untrusted input controls a key used in a deep-merge, deep-clone, or path-set operation, letting an attacker set `__proto__`, `constructor.prototype`, or another special key and modify `Object.prototype` (or a class prototype) itself, affecting every object in the process.

## Where to look
- Sinks in the project's own code: hand-written recursive merge/extend/clone functions, generic `setNestedValue(obj, path, value)`/`setByPath` helpers, JSON-patch or query-string-to-object parsers that walk attacker-supplied keys and assign into an object recursively.
- Anywhere a key from `req.body`, `req.query`, a JSON payload, or a URL is used as a property name in an assignment inside a loop or recursive function (`obj[key] = ...` where `key` is untrusted and the walk isn't guarded).
- Special keys to watch for: `__proto__`, `prototype`, `constructor`, and their nested forms (`a.__proto__.b`, `["constructor"]["prototype"]`).
- This is distinct from a vulnerable *library version* (e.g. an old `lodash.merge`, `deep-extend`, or `qs` with a known prototype-pollution CVE) — that is a dependency finding for the dependency reviewer, not this check. This file is for unsafe *use* in the project's own merge/set code, including passing untrusted keys into an otherwise-current library without a safe-mode option enabled.

## How to confirm
Show untrusted data supplying an object key that reaches a recursive assignment (merge, clone, or path-set) with no check rejecting `__proto__`/`constructor`/`prototype` as a key, and show that the target object or its prototype persists across requests (e.g. a module-level object, a shared config object, or `Object.prototype` itself).

## False-positive traps
- Using `Object.create(null)` or a `Map` as the merge target is safe — there is no prototype chain to pollute.
- Recent versions of well-known deep-merge libraries (current `lodash`, `just-safe-set`) already block `__proto__`/`constructor` keys by default — check the version and changelog before flagging.
- `JSON.parse` followed by `Object.assign(target, parsed)` (shallow, one level) is not vulnerable to nested-key pollution the way a recursive merge is.
- A merge/set function that explicitly allow-lists the permitted top-level keys before recursing is safe even without special-casing `__proto__`.

## Safe patterns
```js
function isUnsafeKey(k) {
  return k === "__proto__" || k === "constructor" || k === "prototype";
}
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (isUnsafeKey(key)) continue;
    if (source[key] && typeof source[key] === "object") {
      target[key] = safeMerge(target[key] ?? {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

## Fix guidance
Reject `__proto__`, `constructor`, and `prototype` as keys in any recursive merge/clone/path-set function; prefer `Map`/`Object.create(null)` for dictionaries built from untrusted keys; keep merge library dependencies current and check their changelog for prototype-pollution fixes (flagged separately as a dependency finding, not here).

## Severity guide
- Impact `high`: pollution reaches a security-relevant property (auth checks, template settings) enabling privilege escalation or RCE.
- Impact `medium`: pollution causes application logic errors or denial of service without direct privilege gain.
- Impact `low`: pollution is reachable but affects only cosmetic or non-security state.
- Exploitability: `high` when unauthenticated or ordinary users can submit arbitrary JSON keys; `medium` when a specific role is needed; `low` for admin-only input.
