#!/usr/bin/env bash
# Stamp a release version into Python, Rust, and TypeScript manifests.
#
# semantic-release owns the version number but ships no Python/npm plugin that
# rewrites these files, so they are stamped by hand. This runs from the
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
stamp_toml_version() {
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

# Rewrites only the root package "version" field (two-space indent).
stamp_package_json_version() {
  local path="$1"
  python3 - "$VERSION" "$path" <<'PY'
import re
import sys

version, path = sys.argv[1], sys.argv[2]
with open(path) as handle:
    source = handle.read()

new, count = re.subn(
    r'(?m)^  "version": "[^"]*"',
    f'  "version": "{version}"',
    source,
    count=1,
)
if count != 1:
    sys.exit(f"{path}: expected one root version field, rewrote {count}")

with open(path, "w") as handle:
    handle.write(new)
PY
}

# Keep package-lock root + packages[""] versions aligned with package.json.
stamp_package_lock_version() {
  local path="$1"
  python3 - "$VERSION" "$path" <<'PY'
import json
import sys

version, path = sys.argv[1], sys.argv[2]
with open(path) as handle:
    data = json.load(handle)

if "version" not in data:
    sys.exit(f"{path}: missing root version")
data["version"] = version
root = data.get("packages", {}).get("")
if root is None or "version" not in root:
    sys.exit(f"{path}: missing packages[''].version")
root["version"] = version

with open(path, "w") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY
}

stamp_toml_version "$ROOT/pyproject.toml"
stamp_toml_version "$ROOT/crates/pii-mcp-native/Cargo.toml"
stamp_package_json_version "$ROOT/typescript/package.json"
stamp_package_lock_version "$ROOT/typescript/package-lock.json"

echo "set version to $VERSION"
