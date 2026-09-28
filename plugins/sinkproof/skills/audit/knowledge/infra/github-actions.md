# GitHub Actions workflows

## What it covers
Workflow files in `.github/workflows/*.yml`. CI runs with repository secrets and write tokens, so a workflow that runs untrusted code or text with those privileges exposes the whole repository and its deployments. Related CWEs: CWE-78 (injection into `run:` steps), CWE-829 (untrusted third-party actions), CWE-250 (excess token permissions).

## Checks
- **Untrusted event data in `run:` steps:** `${{ github.event.* }}` fields that users control — issue and PR titles and bodies, comment bodies, branch names (`github.head_ref`), commit messages — interpolated directly into a shell `run:` script. The expression is expanded before the shell runs.
- **`pull_request_target` or `workflow_run` with a checkout of the PR head** (`ref: ${{ github.event.pull_request.head.sha }}` or similar) followed by build, install or test steps. These triggers run with the base repository's secrets and a write token, so the PR's code runs with them.
- **Unpinned third-party actions:** `uses: owner/action@main`, `@master` or a mutable tag for actions outside `actions/*` and `github/*`. A pinned full commit SHA is the reference point.
- **Over-broad `permissions`:** no top-level `permissions:` block (older repos default to write-all), or `write-all` / `contents: write` on jobs that only read.
- **Secrets reaching untrusted contexts:** secrets passed as env to steps that run PR code, `secrets: inherit` to reusable workflows from other repos, secrets echoed to logs.
- **Self-hosted runners on public repositories** that accept workflows from forks.

## False-positive traps
- Event data passed through `env:` and referenced as `"$VAR"` in the script is not interpolated into the script text; that is the recommended pattern.
- `pull_request_target` workflows that never check out or execute PR code (labeling, commenting, triage) are the intended use and are safe.
- `pull_request` (not `_target`) from forks runs without secrets and with a read-only token.
- First-party `actions/*` pinned to a major tag are widely accepted; report them at low impact at most.

## Fix guidance
1. Move event data into `env:` and quote the variable in the script.
2. Split privileged work: build and test untrusted code in `pull_request`, then use `workflow_run` only to consume artifacts, never to execute them.
3. Pin third-party actions to full commit SHAs and let Dependabot update them.
4. Set `permissions: contents: read` at the top level and grant more per job only where needed.

## Severity guide
- Impact `high`: secrets or a write token are reachable by code or text from an external contributor.
- Impact `medium`: unpinned third-party actions or excess permissions without a direct path for outsiders.
- Impact `low`: hardening gaps on workflows that never see untrusted input.
- Exploitability: `high` when anyone who can open an issue, comment or fork PR triggers the workflow; `medium` when a maintainer label or approval gate is required.
