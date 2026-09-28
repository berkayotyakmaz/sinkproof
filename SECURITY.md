# Security Policy

sinkproof is a security tool, so we take reports about sinkproof itself seriously.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use one of these private channels instead:

1. **GitHub private vulnerability reporting** — on the repository page, open the **Security** tab and choose **Report a vulnerability**.
2. **Email** — bekkobussiness@gmail.com

Please include:
- what the problem is and where (file, instruction or script),
- how it could affect a user of sinkproof (for example: repository text that makes the skill skip findings, run commands, send data out, edit files it should not, or commit changes),
- steps to reproduce, and the sinkproof version (`plugins/sinkproof/.claude-plugin/plugin.json`).

We aim to acknowledge reports within 7 days and to agree on a disclosure date with you once a fix is ready.

## In scope

- The skill, agent instructions and scripts in `plugins/sinkproof/` behaving against the safety rules in the README (read-only until approved fixes, no execution of project code, no source code sent to external services, no commits).
- Knowledge files giving advice that would make code less secure if followed.

## Out of scope

- Vulnerabilities in the deliberately vulnerable applications under `benchmarks/` — they are intentional.
- Findings that sinkproof misses or reports wrongly in your own project. Please open a normal issue for accuracy problems (without sharing your private code).

See also [THREAT-MODEL.md](THREAT-MODEL.md) for the protections and residual risks, and [DISCLAIMER.md](DISCLAIMER.md).
