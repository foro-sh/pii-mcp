# Publishing

`pii-mcp` publishes to **PyPI** and **npm** automatically on merge to `main`
when semantic-release cuts a new version. Nothing is published from a pull
request.

## Packages

| Registry | Package | Source |
| --- | --- | --- |
| PyPI | `pii-mcp` | repo root (`pyproject.toml`) |
| npm | `pii-mcp` | [`typescript/`](typescript/) (JS-only today) |

### PyPI artifacts

| Artifact | Builder | Contents |
| --- | --- | --- |
| Platform wheels (`manylinux` / macOS / Windows) | maturin | Python package + `pii_mcp._native` |
| `py3-none-any` wheel + sdist | hatchling (`uv build`) | Pure Python fallback |

Pip prefers a matching platform wheel; otherwise it installs the pure wheel or
sdist (no Rust toolchain required).

### npm artifacts

The published tarball is the compiled TypeScript package (`dist/`). Optional
napi / Rust native prebuilds are not shipped yet — `npm install pii-mcp` stays
JS-only until that lands.

## What happens on merge

`.github/workflows/release.yml` runs:

1. **commitlint** — rejects commits that don't follow Conventional Commits.
2. **release** — semantic-release analyzes commits. If a release is warranted,
   it stamps the version into `pyproject.toml`,
   `crates/pii-mcp-native/Cargo.toml`, and `typescript/package.json` (+ lock)
   via `scripts/set-version.sh`, updates `CHANGELOG.md`, commits
   `chore(release):`, tags, and creates a GitHub release.
3. **build-wheels** — maturin platform matrix for the release commit
   (maturin `v1.15.0` via pinned maturin-action). Each native-arch job
   smoke-tests the wheel (`using_native()` + a sample scrub) before upload;
   cross-compiled linux aarch64 skips the smoke test. Intel macOS wheels
   build on `macos-15-intel` (macos-13 is retired).
4. **build-sdist** — pure hatchling wheel + sdist via `uv build`.
5. **publish-python** — downloads all artifacts and uploads via OIDC trusted
   publishing.
6. **publish-npm** — builds `typescript/` and runs `npm publish` via OIDC
   trusted publishing (no `NPM_TOKEN`).

## Manual publishing

If an upload fails after the release was tagged, republish from the Actions
tab rather than cutting another release:

- Dispatch **Publish Python** — wheel matrix + pure fallback for the branch
  head (after a release, that is the version-bump commit).
- Dispatch **Publish npm** — rebuilds and publishes `typescript/` for the
  branch head.

## Credentials

Both registries use trusted publishing (OIDC). There is no long-lived publish
token in GitHub secrets for the steady state.

| Registry | Publisher workflow filename | GitHub environment |
| --- | --- | --- |
| PyPI | `release.yml` (automatic) **and** `publish-python.yml` (manual) | `pypi` |
| npm | `release.yml` (automatic) **and** `publish-npm.yml` (manual) | `npm` |

### One-time setup (PyPI)

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
   creates the project and uploads the current version (if needed).

Both workflow files need their own trusted publisher — PyPI cannot authorize
an upload that runs inside a reusable workflow, so the publish steps are
duplicated rather than shared via `workflow_call`.

### One-time setup (npm)

npm trusted publishers attach to an **existing** package. Bootstrap once:

1. Create a GitHub Environment named `npm` on this repository (no secrets
   required for OIDC).
2. Create / claim the unscoped name `pii-mcp` on npm under an account that
   can publish (org or user). The package does not exist yet until the first
   successful publish.
3. **First publish (chicken-and-egg):** trusted publishing cannot be configured
   before the package exists. Either:
   - From a clean checkout of the release commit: `cd typescript && npm ci &&
     npm run build && npm publish --access public` while logged in with
     `npm login`, **or**
   - Temporarily add a granular npm automation token as repo secret
     `NPM_TOKEN`, set `NODE_AUTH_TOKEN` in a one-off local/dispatch publish,
     then remove the secret.
4. On [npmjs.com](https://www.npmjs.com/) → package `pii-mcp` → **Settings** →
   **Trusted Publisher**, add GitHub Actions publishers:

   | Field | Automatic | Manual |
   | --- | --- | --- |
   | Organization or user | `foro-sh` | `foro-sh` |
   | Repository | `pii-mcp` | `pii-mcp` |
   | Workflow filename | `release.yml` | `publish-npm.yml` |
   | Environment | `npm` | `npm` |
   | Allowed actions | include `npm publish` | include `npm publish` |

5. Optionally restrict package publishing access to “Require 2FA and disallow
   tokens” after OIDC works.
6. If the first automatic publish was skipped, dispatch **Publish npm** once
   so registry version matches the latest Git tag / PyPI version.

Do **not** configure `actions/setup-node` `registry-url` for the OIDC publish
jobs — that writes an empty `_authToken` and blocks trusted publishing
([npm/documentation#1960](https://github.com/npm/documentation/issues/1960)).

## Local sanity checks

```bash
uv build                                          # pure wheel + sdist
maturin build --release --out dist                # platform wheel with _native
uv run --with "fastmcp==3.0.0" pytest

cd typescript && npm ci && npm run build && npm pack --dry-run
```
