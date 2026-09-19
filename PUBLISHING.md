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
6. **publish-typescript** — calls `publish-typescript.yml` to build
   `typescript/` and run `npm publish` via OIDC (no `NPM_TOKEN`).

The npm upload is a reusable-workflow call. The PyPI upload cannot be — see
[Credentials](#credentials) — so those steps stay duplicated. Same shape as
`foro-sh/foro`.

## Manual publishing

If an upload fails after the release was tagged, republish from the Actions
tab rather than cutting another release. Dispatching builds the branch head,
which after a release is the commit carrying the version bump.

- **PyPI** — dispatch **Publish Python**.
- **npm** — dispatch **Release** with `publish_npm` checked. It skips the
  release itself and only runs the npm upload. Dispatching *Publish
  TypeScript* directly is not possible, by design — see below.

## Credentials

Both registries use trusted publishing (OIDC). There is no stored token for
either in the steady state.

| Registry | Publisher workflow filename | GitHub environment |
| --- | --- | --- |
| PyPI | `release.yml` (automatic) **and** `publish-python.yml` (manual) | `pypi` |
| npm | `release.yml` — one only | `npm` |

The environment must match the `environment:` on the job performing the
upload.

npm permits only **one** trusted-publisher filename per package, and resolves
the *calling* workflow — so `release.yml` is the only filename that can ever
authenticate an npm publish. Every npm upload, automatic or manual, is
therefore called from that file. `publish-typescript.yml` is
`workflow_call`-only for this reason: triggered directly it would fail
`ENEEDAUTH`, so it deliberately offers no button that cannot work.

PyPI allows several publishers, so it keeps a genuine manual path
(`publish-python.yml`).

They land on the same table for opposite reasons. PyPI [cannot authorize an
upload inside a reusable workflow][pypi-reusable] at all, so its steps are
duplicated into `release.yml`. npm can, but [resolves the *calling*
workflow's filename][npm-reusable] rather than the one holding the publish
step — so the reusable call is fine, and npm simply sees `release.yml`.

npm additionally requires npm ≥ 11.5.1, Node ≥ 22.14, and `id-token: write` on
**both** the calling and the called workflow. `publish-typescript.yml` asserts
the npm version explicitly, so a runner image shipping an older npm fails with
a legible message instead of an auth error that looks like a broken publisher.

Do **not** configure `actions/setup-node` `registry-url` for the OIDC publish
jobs — that writes an empty `_authToken` and blocks trusted publishing
([npm/documentation#1960](https://github.com/npm/documentation/issues/1960)).

[npm-reusable]: https://docs.npmjs.com/trusted-publishers
[pypi-reusable]: https://docs.pypi.org/trusted-publishers/troubleshooting/

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

### One-time setup (npm)

npm trusted publishers attach to an **existing** package. Bootstrap once
(same account/org that already publishes `@foro-sh/foro` can own `pii-mcp`):

1. Create a GitHub Environment named `npm` on this repository (no secrets
   required for OIDC).
2. **First publish (chicken-and-egg):** trusted publishing cannot be configured
   before the package exists. From a clean checkout of a release commit:

   ```bash
   cd typescript && npm ci && npm run build && npm publish --access public
   ```

   (after `npm login`), **or** temporarily use a granular automation token
   once, then remove it.
3. On [npmjs.com](https://www.npmjs.com/) → package `pii-mcp` → **Settings** →
   **Trusted Publisher**, add **one** GitHub Actions publisher:

   | Field | Value |
   | --- | --- |
   | Organization or user | `foro-sh` |
   | Repository | `pii-mcp` |
   | Workflow filename | `release.yml` |
   | Environment | `npm` |
   | Allowed actions | include `npm publish` |

4. Optionally restrict package publishing access to “Require 2FA and disallow
   tokens” after OIDC works.
5. If the registry is behind the Git tag, Actions → **Release** → Run workflow
   with `publish_npm` checked.

## Local sanity checks

```bash
uv build                                          # pure wheel + sdist
maturin build --release --out dist                # platform wheel with _native
uv run --with "fastmcp==3.0.0" pytest

cd typescript && npm ci && npm run build && npm pack --dry-run
```
