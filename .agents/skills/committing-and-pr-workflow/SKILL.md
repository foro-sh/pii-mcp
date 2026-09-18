---
name: committing-and-pr-workflow
description: Use whenever you have made code or doc changes in this repo and are deciding how to land them — enforces committing every change, grouping changes into reviewed PRs by concern, self-reviewing the diff and committing follow-up fixes, and ASKING the user before merging. Triggers on "commit this", "open a PR", "ship it", finishing a task, or any point where work is done but not yet integrated.
---

# Committing & PR Workflow

## Overview

How work gets integrated in this repo. The rule is simple: **nothing stays
uncommitted, everything lands through a reviewed PR, and merges are the user's
call.**

**Core principle:** Commit → group into PRs by concern → self-review → commit
fixes → ask before merging.

**Announce at start:** "I'm using the committing-and-pr-workflow skill to land
this work."

## The Process

### Step 1: Commit every change

- Never leave the working tree dirty at the end of a task. If you changed it,
  commit it.
- Follow **Commit discipline** in `AGENTS.md`: atomic Conventional Commits
  (`<type>(scope): description`). The `.githooks/commit-msg` hook (commitlint)
  enforces the message shape; a bad subject is rejected.
- **Merge commits count too.** commitlint ignores them by default, so Git's
  auto-generated `Merge branch ...` subject slips through — don't let it. When
  resolving conflicts or merging `main` into a branch, replace it with a
  conventional subject, e.g. `chore: merge origin/main into <branch>`.
- Make atomic commits — one coherent, self-contained change per commit that
  builds and passes its checks on its own. A single issue normally produces
  several commits (one per logical step), not one squashed blob. Message
  explains the *why*.
- If your harness asks for a `Co-Authored-By` trailer, use whatever it
  specifies for the model that wrote the commit. Do not invent a vendor or
  copy a stale model name from this file.

### Step 2: Group into PRs by concern

- **Check the tree before branching.** It must be clean and on the branch you
  expect. If it is dirty or on an unexpected branch, another agent is mid-flight
  — **do not `git checkout` over it.** Stop and report the state; branching or
  switching now will reshuffle their uncommitted work.
- **Branch off `main` first** — never commit directly to `main` (it is the
  default and is protected by CI + semantic-release).
- **One PR per concern.** A bug fix and an unrelated feature are two PRs. Don't
  smuggle a refactor into a feature PR. When in doubt, split.
- Keep code and docs-only changes separate unless the docs directly document the
  code in the same PR.
- Remember semantic-release reads commit/PR titles on `main`: `feat:` → minor,
  `fix:` → patch, `docs:`/`chore:` → no release. Title the PR with the type that
  reflects its real impact.

### Step 3: Open the PR

- Push the branch and open the PR against `main` with `gh`.
- Body must have a **Summary** and a **Test plan**, and the Test plan must cover
  both:
  1. **Automated** — what you ran (`pnpm lint`/`pnpm test`, counts, CI status).
  2. **Manual verification** — numbered repro steps a human reviewer can follow
     against a running stack to confirm the change actually works. Required for
     anything touching data handling, security/compliance, or user-visible
     behavior; skip only for changes with no runtime behavior to check (docs,
     comments, pure refactors covered 1:1 by existing tests).
- If your harness adds a generated-with footer to PR bodies, keep whatever it
  requires; do not invent a vendor-specific footer when none is required.

### Step 4: Self-review and commit fixes

- Review your own diff before handing it over — read it, or run `/code-review`.
- If review surfaces issues, **commit the fixes onto the same branch** (don't
  leave them as loose comments). Re-review after fixing.
- Confirm CI is green (`gh pr checks <n>`).

### Step 5: Ask before merging — always

- **Never merge a PR without explicit user approval.** Not even a green,
  reviewed, trivial one.
- When a PR is reviewed and CI is green, surface it and ask: list the PR(s) that
  are ready and ask the user which to merge (e.g. via the AskUserQuestion tool).
- Only after the user says yes: merge with `gh pr merge <n> --merge --delete-branch`,
  then sync local `main`. **Not `--squash`** — squash merging is disabled on
  this repo's branch protection and the API call fails outright. **Not
  `--rebase`** either — the user's stated preference is an actual merge
  commit. Give the merge commit a Conventional Commits subject (commitlint
  ignores merge commits by default, so GitHub's auto-generated `Merge pull
  request #N from ...` subject would slip through unflagged and pollute
  history; semantic-release also reads that subject on `main` to derive the
  version).

## Running multiple agents at once

A single agent uses the main working tree as normal. But if **you** are fanning
out several agents that each commit, they must not share one checkout — parallel
`git checkout`s collide and reshuffle each other's working trees. Launch each
such agent with `isolation: "worktree"` (or have it `EnterWorktree`) so it gets
its own working directory and branch. Don't make worktrees the default for solo
work — each worktree needs its own install, so it only pays off when work is
genuinely concurrent.

## Related

- `finishing-a-development-branch` — generic completion options (merge/PR/cleanup).
