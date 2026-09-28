# Severity rubric

Severity = impact × exploitability. Never assign severity directly: set `impact` and `exploitability`, and `scripts/findings.py` computes severity from the matrix below.

## Impact

Security, logic and dependency findings (SEC, LOG, DEP):
- **high** — account or tenant takeover, code execution, reading or changing other users' sensitive data, financial loss, authentication bypass
- **medium** — limited data exposure, actions that need victim interaction, denial of service of one feature, data integrity problems without direct financial loss
- **low** — information leak without direct harm, hardening gap, defense-in-depth issue

Architecture and principles findings (ARC, PRI):
- **high** — likely to cause production bugs, or blocks safe change in a core area (auth, payments, data model)
- **medium** — slows changes or creates local bug risk
- **low** — readability or consistency

## Exploitability

SEC, LOG, DEP:
- **high** — unauthenticated or any logged-in user, a single request, no special conditions
- **medium** — needs a specific role, victim interaction, a leaked identifier, non-default configuration, or a timing window the attacker cannot trigger at will (a race the attacker can hit by sending parallel requests is `high`)
- **low** — needs insider access, an already compromised component, or unlikely preconditions

ARC, PRI (how often the code path is hit or changed):
- **high** — on every request or in most changes
- **medium** — regularly
- **low** — rarely

## Matrix

| impact | exploitability | severity |
|---|---|---|
| high | high | critical |
| high | medium | high |
| high | low | medium |
| medium | high | high |
| medium | medium | medium |
| medium | low | low |
| low | high | low |
| low | medium | low |
| low | low | low |
