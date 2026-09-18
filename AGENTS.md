# AGENTS.md

Guidance for AI coding agents working in this repository. Prefer this file over
tool-specific instruction files; keep commit and integration rules here so every
agent follows the same contract.

## Commit discipline

Make atomic commits: each commit is one coherent, self-contained change that
builds and passes its checks on its own. A single issue normally produces several
commits — one per logical step — not one squashed commit. Conventional Commits
are enforced by `commitlint` via a Git hook (`<type>(scope): description`).

**Commitlint rules (config-conventional):**
- **Type** (required): lowercase, one of: `feat`, `fix`, `chore`, `ci`, `docs`, `style`, `refactor`, `perf`, `test`
- **Scope** (optional): wrap in parentheses, e.g. `feat(python): add IBAN pack`. Can be any word describing the subsystem.
- **Description** (required): start with lowercase, use imperative mood ("add" not "adds" or "added"), no trailing period, max ~72 chars
- **Body** (optional): separated from description by a blank line, wrapped at 72 chars
- **Breaking changes:** mark with `BREAKING CHANGE: ` in footer if needed

**Examples:**
```
feat(python): add optional Rust scrub backend
fix(typescript): reject empty language pack lists
docs: document native build for Python
chore(ci): run commitlint on PR range
```

Commitlint runs on every commit. If it fails, fix the message and try again (do not use `--no-verify`).

**Merge commits must be conventional too.** commitlint ignores them by default,
so Git's auto-generated `Merge branch ...` subject is *not* rejected — give it a
conventional message anyway (e.g. `chore: merge origin/main into <branch>`)
so history stays uniform.

**Wrap every line of a merge commit body**, same as any other commit. This is
the rule that actually bites, because a PR-merge body is usually pasted prose
rather than a hand-wrapped paragraph. `body-max-line-length` and
`footer-max-line-length` are both **100** under config-conventional, and
commitlint treats the last paragraph of a multi-paragraph body as the footer —
so a two-paragraph summary with long lines fails on `footer-max-line-length`,
not on the body rule you'd expect. Wrap at 72 like everywhere else and neither
can fire.

Getting this wrong is not caught where you'd notice. The Git hook does not run
on a merge performed by GitHub, so the merge lands green and the failure
surfaces in the **release** workflow, whose first step lints the pushed range
and aborts before semantic-release. The result is a merged PR with no tag and
no changelog entry. It self-heals — that step lints only `before..after`, so
the next push to `main` releases everything since the last tag — but the
release for that merge is simply skipped.

**Versioning is automated and pre-GA.** semantic-release derives the version
from commit messages on every push to `main` — never hand-edit a version or
`CHANGELOG.md`. Releases live on the **0.x** line until GA; a breaking change
bumps the minor, not the major (see `.releaserc.json`), so `1.0.0` stays a
deliberate promotion.

For how changes get integrated — commit everything, group into reviewed PRs by
concern, self-review and commit fixes, and **ask before merging** — follow the
`committing-and-pr-workflow` skill under `.agents/skills/`. Never merge a PR
without explicit approval.
