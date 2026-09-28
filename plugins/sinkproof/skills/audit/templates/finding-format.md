# Finding format

Review agents return **only** a JSON array of finding objects — no prose before or after it. Return `[]` when there is nothing to report.

| Field | Required | Values / notes |
|---|---|---|
| `dimension` | always | `SEC` security · `LOG` logic/concurrency · `DEP` dependencies · `ARC` architecture · `PRI` principles |
| `class` | always | kebab-case. Use the knowledge file name when one exists (`idor`, `race-condition`); otherwise a short slug (`god-object`, `open-redirect`) |
| `title` | always | one specific line: "Order lookup has no ownership check" |
| `file` | always | path relative to the project root, forward slashes |
| `line` | always | line of the sink or of the problem |
| `symbol` | always | enclosing function, method or class; `<module>` for top-level code; `<manifest>` for dependency files |
| `impact` | always | `high` · `medium` · `low` — see `rubric/severity.md` |
| `exploitability` | always | `high` · `medium` · `low` — see `rubric/severity.md` |
| `cwe` | SEC, LOG, DEP | e.g. `CWE-639` |
| `owasp` | SEC | e.g. `A01:2021` |
| `evidence` | always | array of strings `description (file:line)`, ordered source → sink. A SEC finding without a complete trail must not be reported |
| `scenario` | SEC, LOG, DEP | what an attacker or user does and what happens. Describe; never include a working exploit payload |
| `fix` | always | concrete change naming the function or file to change |

Never set these yourself:
- `id`, `severity` — added by `scripts/findings.py`
- `verdict` (`confirmed` · `plausible` · `refuted`), `verdict_reason` — added by the verifier

## Example

```json
[
  {
    "dimension": "SEC",
    "class": "idor",
    "title": "Order lookup has no ownership check",
    "file": "src/routes/orders.js",
    "line": 14,
    "symbol": "getOrder",
    "impact": "high",
    "exploitability": "high",
    "cwe": "CWE-639",
    "owasp": "A01:2021",
    "evidence": [
      "req.params.id taken from the URL (src/routes/orders.js:12)",
      "db.query('SELECT * FROM orders WHERE id = ?', [id]) with no user_id condition (src/routes/orders.js:14)",
      "full order row returned to caller (src/routes/orders.js:16)"
    ],
    "scenario": "Any logged-in user requests /orders/<other id> and receives another customer's order, address and payment details.",
    "fix": "In getOrder, add `AND user_id = ?` bound to req.user.id and return 404 when no row matches."
  }
]
```
