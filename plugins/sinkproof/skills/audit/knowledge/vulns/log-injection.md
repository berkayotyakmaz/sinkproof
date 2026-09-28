# Log Injection
CWE-117 · OWASP A09:2021 · ASVS V7.3.1

## What it is
Untrusted data containing newlines or log-format control sequences is written into application logs without neutralization, letting an attacker forge fake log entries, split records, or corrupt structured-log parsing. This file covers forged/broken log entries only, not sensitive data being logged (see `sensitive-data-in-logs` for that).

## Where to look
- Sinks: `logger.info(userInput)`, `console.log(\`User \${email} logged in\`)`, `log.Printf("%s", userInput)` (Go), `logging.info(f"...")` (Python), `Logger.info(userInput)` (Java, Log4j/SLF4J), string-built log lines in any language.
- Especially values placed directly into a log line without a structured/keyed field: usernames, emails, User-Agent, Referer, filenames, free-text form fields.
- Also: log-forwarding or SIEM ingestion code that re-logs a raw upstream header or request body.

## How to confirm
Show untrusted input reaching a log call as part of the message text (not a separate structured field) with no stripping of newlines/control characters, so an attacker can inject a fake timestamp/level line or forge an entry that looks like it came from the application.

## False-positive traps
- Structured loggers that place each value in its own JSON field (`logger.info("login", { email })` with a JSON formatter) are safe — the value cannot break out of the log record's syntax.
- Loggers/appenders that already encode or escape newlines in string fields (many JSON encoders do this automatically) are safe.
- Numeric, boolean, or enum-typed values are not exploitable even when interpolated into a string.
- Log level or logger name is not itself attacker-controlled in typical setups — only the message/argument values are.

## Safe patterns
```js
const logger = require("pino")();
logger.info({ event: "login", email: String(email) }, "user login");
// structured field, not string-concatenated into the message
```

## Fix guidance
Use structured (JSON/keyed) logging so untrusted values sit in their own field rather than the message text; if plain-text logging is unavoidable, strip or encode newlines and control characters from any interpolated value before writing it.

## Severity guide
- Impact `high`: only when the forged/injected content is rendered by an HTML log viewer or dashboard without escaping, so it executes as script in an analyst's browser — report that case as `xss`, not log-injection.
- Impact is otherwise capped at `medium`: forged entries can mislead incident response, hide an attacker's own actions in a security-relevant log, or feed automated alerting/a dashboard causing false signals.
- Impact `low`: cosmetic corruption of low-value application logs.
- Exploitability: `high` when unauthenticated or ordinary users control the logged value; `medium` when a specific role is needed; `low` for admin-only input.
