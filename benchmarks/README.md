# Benchmarks

Small applications with **deliberately planted vulnerabilities**, used to measure how many real issues sinkproof finds (recall) and how many of its findings are real (precision).

**Never deploy or run these applications.** They are insecure on purpose.

Each app has `expected-findings.json`:
- `expected` — issues the audit must find (`required: true`) or should find (`required: false`)
- `safe` — look-alike code that is safe; flagging it counts as a false positive
