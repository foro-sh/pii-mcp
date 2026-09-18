# Publishing

`pii-mcp` publishes to PyPI automatically on merge to `main` when
semantic-release cuts a new version. Nothing is published from a pull request.

## Package

| Registry | Package | Source |
| --- | --- | --- |
| PyPI | `pii-mcp` | repo root (`pyproject.toml`) |

## What happens on merge

`.github/workflows/release.yml` runs:

1. **commitlint** — rejects commits that don't follow Conventional Commits.
2. **release** — semantic-release analyzes commits. If a release is warranted,
   it stamps the version into `pyproject.toml` (`scripts/set-version.sh`),
   updates `CHANGELOG.md`, commits `chore(release):`, tags, and creates a
   GitHub release.
3. **publish-python** — runs only when a release was cut. Builds the exact
   release commit with `uv build` and uploads via OIDC trusted publishing.

## Manual publishing

If an upload fails after the release was tagged, republish from the Actions
tab rather than cutting another release:

- Dispatch **Publish Python**. It builds the branch head (after a release,
  that is the commit carrying the version bump).

Use this once after the first merge of PyPI wiring to upload the current
tagged version (e.g. `1.3.1`) without waiting for the next `feat:` / `fix:`.

## Credentials

PyPI uses trusted publishing (OIDC). There is no stored token.

| Registry | Publisher workflow filename | GitHub environment |
| --- | --- | --- |
| PyPI | `release.yml` (automatic) **and** `publish-python.yml` (manual) | `pypi` |

### One-time setup

1. Create a GitHub Environment named `pypi` on this repository (no secrets
   required for trusted publishing).
2. On [PyPI trusted publishers](https://pypi.org/manage/account/publishing/),
   add pending publishers for project `pii-mcp`:

   | Field | Automatic | Manual |
   | --- | --- | --- |
   | Owner | `foro-sh` | `foro-sh` |
   | Repository | `pii-mcp` | `pii-mcp` |
   | Workflow | `release.yml` | `publish-python.yml` |
   | Environment | `pypi` | `pypi` |

3. After merge, dispatch **Publish Python** once so the pending publisher
   creates the project and uploads the current version.

Both workflow files need their own trusted publisher — PyPI cannot authorize
an upload that runs inside a reusable workflow, so the publish steps are
duplicated rather than shared via `workflow_call`.

## Local sanity checks

```bash
uv build
uv run --with "fastmcp==3.0.0" pytest
```
