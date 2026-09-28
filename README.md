# sinkproof

**Every finding comes with proof.**

An evidence-backed code audit skill for Claude Code. It reviews a codebase along five dimensions — security, logic and concurrency, dependencies, architecture and code principles — verifies every finding by trying to refute it, writes a Markdown report and fixes only the findings you approve.

> **Status:** early development (v0.6). In a blind test on a deliberately vulnerable training application it found 80% of the annotated vulnerabilities, and all 12 sampled findings that were checked by hand were real. Not a substitute for a professional penetration test.

## What makes it different

- **Evidence or nothing:** every security finding carries a source → sink trail with `file:line` references.
- **Adversarial verification:** a separate agent tries to disprove each finding before it reaches the report.
- **Real CVE data:** dependency checks use your ecosystem's audit tool or OSV.dev — never model memory.
- **Safe by default:** read-only until you approve fixes; never runs your code; never sends your source code anywhere (OSV.dev receives package names and versions only); never commits.

## Covered vulnerability classes

36 classes with a dedicated knowledge file (sources, sinks, false-positive traps, safe patterns, fixes), each mapped to CWE, OWASP Top 10 2021 and OWASP ASVS 4.0.3 and checked against those sources with `tools/verify_refs.py`.

| Class | File | CWE |
|---|---|---|
| Broken Function-Level Authorization | `broken-function-level-authz` | CWE-862 |
| OS Command Injection | `command-injection` | CWE-78 |
| CORS Misconfiguration | `cors-misconfig` | CWE-942 |
| CSRF (Cross-Site Request Forgery) | `csrf` | CWE-352 |
| Unrestricted File Upload | `file-upload` | CWE-434 |
| Hardcoded Secrets | `hardcoded-secrets` | CWE-798 |
| HTTP Header / CRLF Injection | `header-injection` | CWE-113 |
| Idempotency / Double-Spend | `idempotency-double-spend` | CWE-837 |
| IDOR (Insecure Direct Object Reference) | `idor` | CWE-639 |
| Insecure Deserialization | `insecure-deserialization` | CWE-502 |
| JWT Authentication Flaws | `jwt` | CWE-347 |
| Log Injection | `log-injection` | CWE-117 |
| Mass Assignment | `mass-assignment` | CWE-915 |
| Missing Rate Limiting | `missing-rate-limit` | CWE-307 |
| Multi-Tenant Isolation Failure | `multi-tenant-isolation` | CWE-668 |
| NoSQL Injection | `nosql-injection` | CWE-943 |
| OAuth / OIDC Misconfiguration | `oauth-misconfig` | CWE-287 |
| Open Redirect | `open-redirect` | CWE-601 |
| Path Traversal | `path-traversal` | CWE-22 |
| Prompt Injection | `prompt-injection` | CWE-1427 |
| Prototype Pollution | `prototype-pollution` | CWE-1321 |
| Race Condition (check-then-act) | `race-condition` | CWE-362 |
| Regular Expression Denial of Service (ReDoS) | `redos` | CWE-1333 |
| Missing Security Headers | `security-headers` | CWE-693 |
| Sensitive Data in Logs | `sensitive-data-in-logs` | CWE-532 |
| Session Management Flaws | `session-management` | CWE-613 |
| SQL Injection | `sql-injection` | CWE-89 |
| Server-Side Request Forgery (SSRF) | `ssrf` | CWE-918 |
| Server-Side Template Injection (SSTI) | `ssti` | CWE-1336 |
| Timing Attack on Secret Comparison | `timing-attack` | CWE-208 |
| TOCTOU (Time-of-Check to Time-of-Use) | `toctou` | CWE-367 |
| Weak Password Hashing | `weak-crypto-password-hashing` | CWE-916 |
| Missing or Weak Webhook Signature Verification | `webhook-signature` | CWE-345 |
| Workflow / State-Machine Bypass | `workflow-bypass` | CWE-841 |
| Cross-Site Scripting (XSS) | `xss` | CWE-79 |
| XML External Entity Injection (XXE) | `xxe` | CWE-611 |

Infrastructure checks: `docker`, `github-actions`.

The security agent also reports clear issues outside these classes (for example disabled TLS certificate verification) with the closest CWE.

## The name

In security analysis, a **source** is where untrusted data enters a program (a form field, a URL parameter, an uploaded file) and a **sink** is where it can do damage (a SQL query, HTML output, a shell command). sinkproof proves every finding with the path from source to sink — and helps make your code *sink-proof*.

## Install

In Claude Code:

```
/plugin marketplace add berkayotyakmaz/sinkproof
/plugin install sinkproof@sinkproof
```

To try a local checkout instead, run `/plugin marketplace add <path-to-your-clone>`.

## Use

```
/sinkproof:audit                  # whole project
/sinkproof:audit src/api          # one folder
/sinkproof:audit --diff main      # changes since a git ref
/sinkproof:audit --only security,deps --focus auth   # skip the scope questions
```

Without `--only`, the audit first asks which dimensions to review and whether to focus on an area, so unneeded reviewers are skipped. The report is written to `audit-reports/YYYY-MM-DD-audit.md`.

## Requirements

Claude Code. Optional: Python 3.8+ (stable finding IDs and OSV lookups), your ecosystem's audit tool (`npm audit`, `cargo audit`, …), Semgrep.

## Responsible use

sinkproof is a defensive tool for reviewing code you own or are authorized to review. It does not run exploits or test live systems. Findings can be wrong or incomplete, and it is not a substitute for a professional penetration test. See [DISCLAIMER.md](DISCLAIMER.md) before use, and [THREAT-MODEL.md](THREAT-MODEL.md) for how sinkproof protects itself when the code it reviews is hostile.

## Contributing

New vulnerability classes, better false-positive traps and benchmark cases are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem in sinkproof itself, see [SECURITY.md](SECURITY.md).

## Contact

For collaboration and questions: **bekkobussiness@gmail.com**

## License

MIT
