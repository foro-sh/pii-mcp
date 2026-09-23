# Detector autoresearch

Instructions for an agent that improves the PII detectors unattended, in the
style of Karpathy's autoresearch: change one thing, score it, keep it only if
the score improves, and repeat.

## Setup (once per run)

1. Create a branch off `main`: `git checkout -b autoresearch/<yyyy-mm-dd>`.
2. Save the performance baseline for this machine: `python eval/score.py --save-baseline`.
3. Run `python eval/score.py` and record the result as the first row of
   `eval/results.tsv` (header below). This loss is the number to beat.

## What you may change

- `src/pii_mcp/detectors.py` only. That covers patterns, validators, and
  helpers. You may also change detector order in `_detectors_for` in
  `src/pii_mcp/scrub.py`.

## What you must not change

- Anything under `eval/`, meaning the generators, templates, scorer, and
  gates. The score is only meaningful if the ruler stays fixed.
- Anything under `tests/`. You may not delete, skip, or weaken a test. If a
  test blocks a change you believe is right, write the case up in
  `eval/results.tsv` and move on.
- The Rust (`crates/`) and TypeScript (`typescript/`) backends. A human
  ports the accepted changes afterwards.
- Never run `--split holdout` and never set `PII_EVAL_HOLDOUT_SEED` or
  `PII_EVAL_HOLDOUT_TEMPLATES`. Never read files outside the repository.
  Never push.

## The loop

Loop until you are interrupted. Do not stop to ask for confirmation.

1. Run `python eval/score.py`. Read the `leaks`, `fps`, and `overreach`
   buckets and the printed examples.
2. Pick the bucket with the most weighted damage (a leak costs 3, a false
   positive 1, an overreach 0.5). Work out the *general* cause from several
   examples, not just one.
3. Make one focused change.
4. Run `python eval/score.py` again. It accepts the change only when
   **all** of the following hold:
   - `ok` is `true`, which means the pytest, ReDoS, and performance gates
     all pass.
   - `loss` beat the best loss so far by at least `0.0005`.
5. If the change is accepted, commit it as
   `fix(detectors): <what and why>` and append a `keep` row to the results.
6. If it is rejected, restore the files with
   `git checkout -- src/pii_mcp` and append a `discard` row. The row must
   still say what you tried and why it failed, so the idea is not retried.
7. Go back to step 1.

`eval/results.tsv` is tab-separated and never committed:

```
commit	loss	leak_rate	fp_rate	overreach_rate	status	description
```

## Rules for a good change

- **Generalize, don't memorize.** Never put a literal value, domain, or
  number from the eval output into a pattern or an allowlist. Every rule
  must be justified by the format's specification: its checksum, structure,
  issuer ranges, or separator conventions. A reviewer will reject changes
  that only help the dev seed.
- **Recall first.** Never trade a leak for a false positive. If a fix reduces
  false positives but adds even one leak bucket, discard it.
- **Keep regexes linear.** Use bounded quantifiers and no nested unbounded
  repetition. The ReDoS gate catches only the obvious cases.
- **Ignore `ambiguous_masked`.** It is reported but not scored. Bare 9-digit
  ids, 4-part versions, and plain decimal pairs cannot be told apart from
  PII by pattern alone, so don't try.
- **Document it.** Add a docstring or comment explaining the rule, in the
  same style as the surrounding code.
- **Simplicity counts.** A change that matches the current loss with less
  code is a win. Commit it with the reason.

## After the run (human)

1. Review the `keep` commits. Revert anything that looks like memorization.
2. Check for overfitting on data the agent never saw. The holdout uses
   fresh values from a secret seed, placed in contexts from your own
   template file:

   ```
   PII_EVAL_HOLDOUT_SEED=<secret> PII_EVAL_HOLDOUT_TEMPLATES=<file> \
       python eval/score.py --split holdout --quick
   ```

   Keep the template file outside the repository. Write one context per
   line, with `{}` exactly once where the value goes; `\n` and `\t` are
   decoded, and `#` starts a comment. You need at least 5 lines, and
   different shapes from `TEMPLATES` in `eval/generators.py` are best:
   CSV/TSV rows, YAML, HTML attributes, query strings, chat transcripts,
   stack traces, markdown lists. Record the holdout loss before the run.
   Afterwards it should drop roughly as much as the dev loss.
3. Port the kept changes to `crates/pii-core` and `typescript/src`, then
   confirm the backends still agree:
   `maturin develop --release && python eval/parity.py`, followed by the
   TypeScript test suite.
4. Squash or regroup the commits into atomic `fix:` commits per
   `AGENTS.md`, then open the PR.
