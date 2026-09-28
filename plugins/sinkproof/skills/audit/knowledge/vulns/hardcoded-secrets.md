# Hardcoded Secrets
CWE-798 · OWASP A07:2021 · ASVS V2.10.4

## What it is
A credential — API key, database password, private key, signing secret, OAuth client secret — is embedded directly in source code, config committed to version control, or a client-side bundle, instead of being loaded from a secret store or environment at runtime.

## Where to look
- Source and config files: string literals assigned to variables named `apiKey`, `secret`, `password`, `token`, `privateKey`, connection strings with embedded credentials (`postgres://user:pass@host`).
- Committed `.env`, `application.properties`, `settings.py`, `appsettings.json`, Terraform/CloudFormation files with literal values instead of variable references.
- Client-side/mobile bundles: secrets baked into JS sent to the browser, or into a compiled mobile app — these are extractable by anyone.
- CI config (`.github/workflows/*.yml`, `Jenkinsfile`) with credentials inline instead of using the platform's secret store.
- Private key material (`-----BEGIN PRIVATE KEY-----`) checked into the repo.

## How to confirm
Show the literal secret value's location and that it is (a) not a documented placeholder/example and (b) reachable by anyone with repo or bundle access, i.e. broader than the people who should hold that credential. Confirm the value looks like real credential material (proper length/format for its type), not a variable name or a reference to an environment variable/secret manager call.

## False-positive traps
- Values in test fixtures, mocks, or unit tests that are clearly fake (`"test-api-key"`, `"password123"` used only for local test assertions, well-known public test keys like Stripe's published test-mode keys) are not real secrets — verify they're never used against a live/production service.
- Placeholders in `.env.example`, `.env.sample`, or README setup instructions (`API_KEY=your_api_key_here`, `DATABASE_URL=postgres://user:password@localhost/db`) are documentation, not leaked secrets.
- Public keys (TLS certificates, JWT/SSH public keys, public OAuth client IDs) are meant to be public — only the matching *private* key or client *secret* is sensitive.
- Code that reads a secret from `process.env.X`/`os.environ["X"]`/a secrets-manager SDK call is the fix, not an instance of this finding, even though the variable name contains "secret" or "key".

## Safe patterns
```js
// Loaded from environment / secret manager at runtime, never in source.
const apiKey = process.env.PAYMENTS_API_KEY;
if (!apiKey) throw new Error("PAYMENTS_API_KEY is not configured");
```

## Fix guidance
Move the secret to environment variables or a secrets manager (Vault, AWS/GCP/Azure secret managers, platform-native config); remove it from source and config files; rotate the exposed credential immediately, since removing it from the latest commit does not remove it from git history; add secret-scanning to CI to catch recurrences; never ship secrets in client-side bundles — proxy calls that need them through a server.

## Severity guide
- Impact `high`: a live production credential with broad access (cloud account keys, database admin credentials, payment provider secret keys) committed to a repo or shipped to clients.
- Impact `medium`: a scoped or lower-privilege credential, or one in a private repo with limited access, still exploitable if that access is breached.
- Impact `low`: an expired, rotated, or clearly non-production credential left in history.
- Exploitability: `high` when the secret is reachable in a public repo or a client-side bundle anyone can inspect; `medium` when it requires private repo or internal CI access first.
