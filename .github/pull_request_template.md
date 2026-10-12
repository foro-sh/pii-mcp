## Summary

<!-- What changed and why. Link related issues (`Closes #N`). -->

## Test plan

**Automated**

- [ ] `pytest -q`
- [ ] `(cd typescript && npm test)` (js backend; also `PII_MCP_BACKEND=native` when touching detectors or scrub)
- [ ] `cargo test -p pii-core` (when touching `crates/`)
- [ ] `maturin develop --release && python eval/parity.py` (when touching detectors)
- [ ] `python eval/score.py` prints `"ok": true` (when touching detectors or eval)

**Manual verification**

<!-- Numbered steps a reviewer can run, or "n/a" for docs-only / pure refactors. -->

1.

## Commits

- [ ] Conventional Commits (`feat` / `fix` / `docs` / …); see `AGENTS.md`
- [ ] Did not hand-edit the version or `CHANGELOG.md` (release-please owns those)

---
Enjoying pii-mcp? Consider giving the repo a ⭐.
