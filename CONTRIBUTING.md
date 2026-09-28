# Contributing to sinkproof

Thanks for helping. The most valuable contributions are **better knowledge files** and **benchmark cases** that prove them.

## Ground rules

- Everything is written in English.
- Content is defensive: describe sources, sinks, checks, safe code and fixes. Never add working exploit payloads, including in benchmarks.
- Precision matters more than coverage. A rule that causes false alarms is worse than no rule.
- Do not include code or findings from private projects.

## Project layout

| Path | What lives there |
|---|---|
| `plugins/sinkproof/skills/audit/SKILL.md` | The orchestrator: phases, dispatch, report, fix flow |
| `plugins/sinkproof/skills/audit/agents/` | Instructions for each reviewer and the verifier |
| `plugins/sinkproof/skills/audit/knowledge/vulns/` | One file per vulnerability class |
| `plugins/sinkproof/skills/audit/knowledge/infra/` | CI and container checks |
| `plugins/sinkproof/skills/audit/scripts/` | Deterministic helpers (finding IDs, severity, OSV lookups) |
| `benchmarks/` | Deliberately vulnerable apps with `expected-findings.json` |
| `tools/verify_refs.py` | Checks CWE / OWASP / ASVS references against primary sources |

## Adding or improving a vulnerability class

1. Create `knowledge/vulns/<class-name>.md` (kebab-case; the file name is the class name agents report). Copy the structure of an existing file:
   - line 1: `# Title`
   - line 2: `CWE-<n> · OWASP A<nn>:2021 · ASVS V<x.y.z>`
   - sections, in this order: `What it is`, `Where to look`, `How to confirm`, `False-positive traps`, `Safe patterns`, `Fix guidance`, `Severity guide`
2. **False-positive traps** need at least three entries, including the framework protections that make a pattern safe.
3. The severity guide gives `Impact` and `Exploitability` hints only; severity itself is computed from `rubric/severity.md`.
4. If the class overlaps another one, say in "What it is" which class to use when.
5. Verify the references:
   ```
   python tools/verify_refs.py plugins/sinkproof/skills/audit/knowledge/vulns/<class-name>.md
   ```
   It must print `"ok": true`, and the CWE name and ASVS text it prints must fit the topic. If OWASP Top 10 2021 does not map the CWE, use the closest category and add the sentence `OWASP Top 10 2021 does not map CWE-<n> to a category; A<nn> <name> is the closest fit.`
6. **Add a benchmark case** in `benchmarks/<app>/`: one vulnerable function and, where possible, a safe look-alike. List them in `expected-findings.json` under `expected` and `safe`.

## Tests

Run the whole suite before opening a pull request:

```
python -m unittest discover -s tests
```

Scripts use the Python standard library only (3.8+). Please keep it that way.

## Pull requests

- One topic per pull request.
- Describe what you changed and how you verified it (test run, reference check, and, if you ran the skill, what it found on the benchmark).

## Contact

For collaboration or questions: bekkobussiness@gmail.com. For security issues, see [SECURITY.md](SECURITY.md).
