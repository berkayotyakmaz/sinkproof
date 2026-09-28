# Docker images and Compose files

## What it covers
`Dockerfile*`, `docker-compose*.yml` and `compose*.yml`. Container settings decide how much a compromised application can do on the host and what secrets ship inside the image. Related CWEs: CWE-250 (running with unnecessary privileges), CWE-538 (secrets in image layers), CWE-1104 (unmaintained base images).

## Checks
- **Runs as root:** no `USER` instruction in the final stage, or `USER root` at the end.
- **Secrets in the image:** `ENV` or `ARG` holding keys, passwords or tokens; `COPY` of `.env`, private keys or credential files; secrets removed in a later layer (they remain in the earlier one). Check `.dockerignore` for what the build context includes.
- **Base images:** `latest` or no tag, end-of-life versions (verify against endoflife.date rather than memory), large full-OS images where a slim or distroless image would do.
- **Compose privileges:** `privileged: true`, `network_mode: host`, mounting `/var/run/docker.sock` or host root paths, `cap_add: ALL`.
- **Exposed services:** database, cache or debug ports published on all interfaces (`"5432:5432"` rather than `"127.0.0.1:5432:5432"`), debug flags enabled in production targets.

## False-positive traps
- Multi-stage builds: only the final stage ships. Root or build secrets in an earlier stage are fine if nothing is copied from it but build output — but check that `COPY --from` does not pull secret files.
- Secrets passed with `RUN --mount=type=secret` do not persist in layers. `ARG` and `ENV` values do (visible in `docker history`), so report secrets passed that way.
- Placeholders such as `change-me` or values taken from `${VAR}` in Compose are not leaked secrets; say so instead of reporting a credential.
- Compose files clearly for local development (`docker-compose.dev.yml`, ports bound to localhost) deserve at most low impact.

## Fix guidance
1. Add a non-root `USER` in the final stage and make application files read-only for it.
2. Pass secrets at runtime (orchestrator secrets, env from a secret store) or with BuildKit secret mounts; add sensitive files to `.dockerignore`.
3. Pin base images to a supported version tag, ideally with a digest, and rebuild regularly.
4. Drop `privileged`, host networking and socket mounts; bind internal ports to localhost or an internal network.

## Severity guide
- Impact `high`: real secrets baked into a published image, or a container with host-level access (`privileged`, docker socket) running internet-facing code.
- Impact `medium`: root containers running internet-facing code, EOL base images, internal services exposed on all interfaces.
- Impact `low`: missing hardening on internal or development-only images.
- Exploitability: `high` when the image is public or the service is internet-facing; `medium` when an application compromise is needed first.
