#!/usr/bin/env bash
# Stamp a release version into pyproject.toml.
#
# semantic-release owns the version number but ships no Python plugin, so the
# Python manifest has to be rewritten by hand. This runs from the release's
# `prepareCmd`, which means the bumped file lands *inside* the same
# `chore(release):` commit that @semantic-release/git creates — and therefore
# inside the tag.
set -euo pipefail

VERSION="${1:?usage: set-version.sh <version>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Rewrites only the first `version = "..."` at column 0, which is
# [project].version. A dependency pin written the same way further down the
# file must not be touched — and if the anchor ever stops matching exactly
# once, fail loudly rather than release an unbumped package.
python3 - "$VERSION" "$ROOT/pyproject.toml" <<'PY'
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

echo "set version to $VERSION"
