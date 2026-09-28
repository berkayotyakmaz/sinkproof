# TOCTOU (Time-of-Check to Time-of-Use)
CWE-367 · OWASP A04:2021 · ASVS V11.1.6

OWASP Top 10 2021 does not map CWE-367 to a category; A04 Insecure Design is the closest fit.

## What it is
Code checks a property of a filesystem path, external resource, or permission, then later acts on that same path/resource assuming the check still holds — but the resource can change between the check and the use (a symlink swapped in, a file replaced, permissions changed). This is the filesystem/external-resource sibling of `race-condition.md`: use `race-condition` for shared application/business state (balances, coupons, counters) protected by the database, and use `toctou` specifically when the check and use are against the filesystem, an external process, or an OS-level resource outside transactional control.

## Where to look
- File existence/permission checks followed by a separate open/write: `os.path.exists()` then `open()`, `access()` then `open()`, `is_file()` then read.
- Temp file creation: predictable temp file names created in a shared directory, checked for absence then created (classic symlink-attack pattern).
- Upload handling: validating a file (type/size/virus-scan) at one path, then moving/using a file from a path an attacker could have swapped in the meantime.
- Privilege checks against an external system (file ownership, container/VM state) that isn't re-verified at the moment of use.
- Node: `fs.existsSync()` followed by `fs.writeFileSync()`/`fs.createWriteStream()` on the same path without `O_EXCL`/exclusive flags.

## How to confirm
Show the check (stat/exists/permission call) and the later use (open/write/exec) as separate operations against the same path/resource, with no atomic combined operation and no re-verification immediately before use. Confirm an attacker or another process could plausibly alter the resource in that window (shared/world-writable directory, predictable filename, concurrent multi-user access).

## False-positive traps
- Using atomic OS primitives already closes the gap: `open(path, O_CREAT | O_EXCL)`, `mkstemp`, language-level "create new file, fail if exists" APIs — these are safe even though they "check" internally.
- Files in a directory only the application process can write to (no other process/user has access) have no attacker-controlled window — check directory permissions before flagging.
- A check purely for a better error message, immediately followed by an atomic operation that would itself fail safely if the check were wrong, is not exploitable — confirm the *use* step isn't also protected.
- Don't confuse this with `race-condition`: if the resource is a database row or an in-memory counter rather than a filesystem/OS resource, file it as `race-condition` instead.

## Safe patterns
```python
import os
fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
with os.fdopen(fd, "wb") as f:
    f.write(data)
```

## Fix guidance
Replace separate check-then-act steps with a single atomic OS operation (`O_CREAT|O_EXCL`, `mkstemp`, rename-based atomic replace). Use private, per-process temp directories rather than shared world-writable ones. Where atomicity isn't available, re-verify immediately before use and handle the failure case explicitly rather than assuming the check still holds.

## Severity guide
- Impact `high`: leads to arbitrary file overwrite/read, privilege escalation, or code execution via a swapped symlink/file.
- Impact `medium`: leads to data corruption or denial of service without direct privilege gain.
- Impact `low`: theoretical race with negligible practical impact.
- Exploitability: `high` when the window is in a shared/multi-user writable location reachable by an attacker; `medium` when it requires local access or precise timing the attacker cannot fully control.
