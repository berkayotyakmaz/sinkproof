# Disclaimer

sinkproof is a **defensive code review tool**. It reads source code and reports weaknesses so that developers can fix them. Please read this notice before using it.

## Authorized use only

- Use sinkproof only on code that you own, or that you have explicit permission from the owner to review.
- Reviewing, testing or attacking systems without authorization may be illegal in your jurisdiction. You are solely responsible for making sure your use complies with all applicable laws, regulations, contracts and policies.
- sinkproof does not run exploits, send attack traffic or test live systems. Do not use its findings to attack systems you are not authorized to test.

## No warranty

- sinkproof is provided "as is", with **no warranty** of any kind, as stated in the [MIT License](LICENSE). The authors and contributors are not liable for any damage, data loss, security incident or other consequence arising from its use.
- Findings are produced by an AI-assisted analysis. They can be incomplete or wrong: real vulnerabilities may be missed, and reported issues may not be exploitable.
- A clean report does **not** mean the code is secure.

## Not a substitute for professional review

sinkproof is **not a substitute** for a professional penetration test, a security audit by qualified people, or compliance certification. Use it as one input to your security process, not as the final word.

## Fixes

When you approve fixes, sinkproof edits your working copy. It never commits. Review every change, run your own tests and take responsibility for what you merge and deploy.

## Benchmark applications

The applications under [`benchmarks/`](benchmarks/) are **deliberately vulnerable**. They exist only to measure the tool. Never deploy them, run them on a network, or copy their code into real projects.

## Data and privacy

sinkproof runs inside your Claude Code session. Your source code is processed by the AI model you use with Claude Code, under that service's terms. The dependency check sends only package names and versions to OSV.dev; no source code is sent there.
