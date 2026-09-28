# Path Traversal
CWE-22 · OWASP A01:2021 · ASVS V12.3.1

## What it is
Untrusted input is used to build a filesystem path without neutralizing `..` or absolute-path segments, letting an attacker read, write, or delete files outside the intended directory.

## Where to look
- Node: `fs.readFile(path.join(base, req.params.name))`, `fs.createReadStream`, `res.sendFile`, `express.static` with a user-controlled root.
- Python: `open(os.path.join(base, filename))`, `send_file`, `send_from_directory` without `safe_join`, `zipfile`/`tarfile` extraction with attacker-controlled member names.
- PHP: `include`/`require`/`file_get_contents`/`fopen` built from `$_GET`/`$_POST`.
- Ruby: `File.open(File.join(base, params[:file]))`, `send_file`.
- Java: `new File(base, userInput)`, `Paths.get(base, userInput)` without normalization/containment check.
- Go: `os.Open(filepath.Join(base, r.URL.Query().Get("file")))`, `http.ServeFile`.
- Also: file-upload destination paths, archive extraction (zip slip), template/include-file selection by name.

## How to confirm
Show untrusted input reaching a path-building or file-open call with no normalization/containment check afterward (no verification that the resolved path stays under the intended base directory).

## False-positive traps
- Filenames validated against a strict allow-list or regex (e.g. only `[a-zA-Z0-9_-]+\.png`) before use are safe.
- Framework helpers that resolve and verify containment (`send_from_directory` with Werkzeug's `safe_join`, Node's `path.resolve` + explicit `startsWith(base)` check) are safe.
- An ID used to look up a path from a database/mapping (rather than the raw filename) is not path traversal even though a "file" is ultimately served.
- Reading a fixed, hardcoded path with no user-controlled segment at all is not vulnerable, even if adjacent code in the same function does take user input.
- `res.sendFile(name, { root })` and `express.static(root)` already resolve against `root` and reject a resolved path that escapes it — the containment check is built in; don't flag these for lacking an additional manual check unless `root` itself is user-controlled.

## Safe patterns
```js
const path = require("path");
const base = path.resolve("/var/app/uploads");
const target = path.resolve(base, req.params.name);
if (!target.startsWith(base + path.sep)) return res.status(400).end();
res.sendFile(target);
```

## Fix guidance
Resolve the full path and verify it stays within the intended base directory before use; prefer an allow-list of filenames or a database-backed ID instead of a raw path segment; when extracting archives, reject entries whose resolved path escapes the destination directory (zip slip).

## Severity guide
- Impact `high`: arbitrary file read/write reaching secrets, source code, or other users' data, or leading to code execution.
- Impact `medium`: read access limited to non-sensitive files within a broader filesystem area.
- Impact `low`: traversal confined to a low-value directory with no sensitive content.
- Exploitability: `high` when unauthenticated or ordinary users control the filename; `medium` when a specific role is needed; `low` for admin-only input.
