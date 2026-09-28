# OS Command Injection
CWE-78 · OWASP A03:2021 · ASVS V5.3.8

## What it is
Untrusted data reaches a shell command, letting an attacker inject additional commands or arguments that the operating system executes.

## Where to look
- Node: `child_process.exec`, `execSync`, `spawn(cmd, { shell: true })`.
- Python: `os.system`, `subprocess.run(..., shell=True)`, `subprocess.Popen(cmd, shell=True)`, `os.popen`.
- PHP: `exec`, `shell_exec`, `system`, `passthru`, `` `backticks` ``.
- Ruby: `` `backticks` ``, `system("... #{x}")`, `` Kernel#`  ``, `IO.popen`.
- Java: `Runtime.exec(String)`, `ProcessBuilder` given a single concatenated string passed to a shell (`sh -c`).
- Go: `exec.Command("sh", "-c", userInput)`.
- Also: build/CI scripts, ImageMagick/ffmpeg wrappers, git/archive-extraction helpers invoked with shell strings.

## How to confirm
Trace untrusted input into a command string or into an argument passed to a shell (`shell=True`, `sh -c`, `exec()` with concatenation). Confirm there is no argument-array API or allow-list in between.

## False-positive traps
- Argument-array APIs without a shell (`execFile`, `spawn(cmd, args)` without `shell: true`, `subprocess.run([cmd, arg1, arg2])`, `ProcessBuilder(cmd, arg1, arg2)`) are safe — the OS does not re-parse arguments through a shell.
- A fixed command with only numeric or allow-listed enum arguments is safe even if built from a string.
- Library wrappers that internally use argument arrays (many image/PDF processing bindings) are safe even though the call looks like a raw command.
- Input already validated against a strict allow-list (e.g. a fixed set of filenames) before reaching the sink is safe.
- Argument-array APIs still allow option/flag injection (CWE-88) when a user-controlled value is passed as an argument to a command that interprets leading `-`/`--` as an option (e.g. `git`, `tar`, `curl`) — a value like `--upload-pack=...` or `-oProxyCommand=...` changes behavior even with no shell. Require a `--` separator before user-controlled arguments, or reject values starting with `-`.
- On Windows, Node's `spawn`/`execFile` invoking a `.bat`/`.cmd` file goes through `cmd.exe` even without `shell: true`, so shell metacharacters in arguments are re-parsed — treat this the same as `shell: true`.

## Safe patterns
```js
const { execFile } = require("child_process");
execFile("convert", [inputPath, "-resize", "200x200", outputPath]);
```

## Fix guidance
Prefer library APIs over shelling out. When a subprocess is required, use the argument-array form and never `shell: true`/`shell=True`. Validate any filename or argument against an allow-list, and never build a command by string concatenation.

## Severity guide
- Impact `high`: leads to arbitrary code execution on a server with access to sensitive data or internal systems.
- Impact `medium`: limited command execution in a sandboxed or low-privilege context.
- Impact `low`: execution constrained to a narrow, already-safe set of operations.
- Exploitability: `high` when unauthenticated or ordinary users control the input; `medium` when a specific role is needed; `low` for admin-only or local-only input.
