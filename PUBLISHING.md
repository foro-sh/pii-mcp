# Publishing

Feature PRs merge to `main` without publishing. release-please opens (or
updates) one Release PR that accumulates them; merging *that* PR cuts the
version and publishes to PyPI. Nothing is published from a pull request,
including the Release PR itself.

## Package

| Registry | Package | Source |
| --- | --- | --- |
| PyPI | `pii-mcp` | repo root (`pyproject.toml`) |

Artifacts per release:

| Artifact | Builder | Contents |
| --- | --- | --- |
| Platform wheels (`manylinux` / macOS / Windows) | maturin | Python package + `pii_mcp._native` |
| `py3-none-any` wheel + sdist | hatchling (`uv build`) | Pure Python fallback |

Pip prefers a matching platform wheel; otherwise it installs the pure wheel or
sdist (no Rust toolchain required). Published artifacts are pattern Tier 1
only; in-process NER is not part of this package.

## What happens on merge to main

Commit messages are linted on the PR (`commitlint.yml`). On every push to
`main`, `.github/workflows/release.yml` runs:

1. **release** — release-please. An ordinary `feat`/`fix` merge opens or
   updates the Release PR (`chore(main): release x.y.z`), which bumps
   `CHANGELOG.md`, `pyproject.toml` and `crates/pii-mcp-native/Cargo.toml`
   (`release-please-config.json`). `sync-cargo-lock.yml` then commits the
   matching `Cargo.lock` onto the PR. `docs`/`ci`/`chore` commits do not open
   one. Merging the Release PR tags it and creates the GitHub release; the
   jobs below run only then.
2. **build-wheels** — maturin platform matrix for the release commit
   (maturin `v1.15.0` via pinned maturin-action). Each native-arch job
   smoke-tests the wheel (`using_native()` + a sample scrub) before upload;
   cross-compiled linux aarch64 skips the smoke test. Intel macOS wheels
   build on `macos-15-intel` (macos-13 is retired).
3. **build-sdist** — pure hatchling wheel + sdist via `uv build`.
4. **publish-python** — downloads all artifacts and uploads via OIDC trusted
   publishing.

## Manual publishing

If an upload fails after the release was tagged, republish from the Actions
tab rather than cutting another release:

- Dispatch **Publish Python**. It builds the branch head (after a release,
  that is the commit carrying the version bump), including the same wheel
  matrix and pure fallback.

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
uv build                                          # pure wheel + sdist
maturin build --release --out dist                # platform wheel with _native
uv run --with "fastmcp==3.0.0" pytest
```
