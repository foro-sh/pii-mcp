#!/usr/bin/env bash
# Stamp a release version into pyproject.toml and the PyO3 crate manifest.
#
# semantic-release owns the version number but ships no Python plugin, so the
# Python manifest has to be rewritten by hand. The native crate version is kept
# in lockstep so maturin wheels match the PyPI package. This runs from the
# release's `prepareCmd`, which means the bumped files land *inside* the same
# `chore(release):` commit that @semantic-release/git creates — and therefore
# inside the tag.
set -euo pipefail

VERSION="${1:?usage: set-version.sh <version>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Rewrites only the first `version = "..."` at column 0. For pyproject.toml
# that is [project].version; for the crate it is [package].version. A
# dependency pin written the same way further down must not be touched — and
# if the anchor ever stops matching exactly once, fail loudly rather than
# release an unbumped package.
stamp_version() {
  local path="$1"
  python3 - "$VERSION" "$path" <<'PY'
import re
import sys

version, path = sys.argv[1], sys.argv[2]
with open(path) as handle:
    source = handle.read()

new, count = re.subn(
    r'(?m)^version = "[^"]*"$', f'version = "{version}"', source, count=1
)
if count != 1:
    sys.exit(f"{path}: expected one top-level version line, rewrote {count}")

with open(path, "w") as handle:
    handle.write(new)
PY
}

stamp_version "$ROOT/pyproject.toml"
stamp_version "$ROOT/crates/pii-mcp-native/Cargo.toml"

echo "set version to $VERSION"
