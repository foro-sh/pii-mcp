"""External benchmark: score pii-mcp against ai4privacy text.

    python eval/external.py                  # email/phone/address/structured-id scores
    python eval/external.py --ner             # also print person/place (context only)
    python eval/external.py --n 500 --seed 1  # larger sample, different draw

Opt-in: needs the ``datasets`` package (``pip install -e ".[eval]"``) and
network access to the Hugging Face Hub. The validation split is streamed on
every run (about two minutes for the default sample) and never stored in
this repository. ``PII_MCP_BACKEND`` picks the backend (default ``python``).

Dataset: ``ai4privacy/pii-masking-openpii-1m``, pinned to revision
``DATASET_REVISION`` so a seed always draws the same texts. It is synthetic
text with PII annotations, licensed CC BY 4.0. Credit: Ai4Privacy / Ai Suisse
SA, https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m. The
``ai4privacy/pii-masking-300k`` dataset named in issue #56 is not used: its
license allows only non-commercial research use and no derivative products,
which this MIT-licensed, commercially used package cannot meet.

The dataset has no IP, MAC, IBAN or coordinate labels, so recall for those
categories is not scored here; ``eval/score.py`` covers them. Runs pii-mcp
labels ``IP``, ``IBAN``, ``BIC``, ``MAC``, ``IMEI``, ``LOCATION`` or
``LICENSE_PLATE`` get no per-group precision for the same reason; they still
count in ``no_gold_overlap_rate``.

Scoring: each scrubbed text is aligned back to its source (see
``_align_runs``). A gold span counts as caught when none of its alphanumeric
characters survive unchanged; a gold span with no alphanumeric characters is
not scored. Gold labels are grouped: ``person`` (GIVENNAME, SURNAME),
``street_address`` (STREET, BUILDINGNUM, ZIPCODE), ``place`` (CITY),
``email`` (EMAIL), ``phone`` (TELEPHONENUM) and ``structured_id``
(SOCIALNUM, TAXNUM, IDCARDNUM, PASSPORTNUM, DRIVERLICENSENUM,
CREDITCARDNUMBER). ``person`` and ``place`` are printed only with ``--ner``:
the pattern layer does not target prose names or place names (README
"Scope"), so they are context, never a target.

Precision per group and the share of masked runs with no gold overlap both
come from pii-mcp's ``[LABEL]`` placeholders: each run is attributed to the
category in its placeholder and checked against gold spans of the matching
group.

The last line printed is machine-readable JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

from score import PLACEHOLDER_RE  # noqa: E402

from pii_mcp import scrub_text  # noqa: E402

_SPLIT_RE = re.compile(f"({PLACEHOLDER_RE.pattern})")

DATASET = "ai4privacy/pii-masking-openpii-1m"
DATASET_REVISION = "ecfdc547f4a0955600cfe6ab98ba2a162207fcc0"
DATASET_URL = "https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m"
LANGUAGES: tuple[str, ...] = ("en", "nl", "de")
DEFAULT_N = 300
DEFAULT_SEED = 0

GROUPS: dict[str, tuple[str, ...]] = {
    "person": ("GIVENNAME", "SURNAME"),
    "street_address": ("STREET", "BUILDINGNUM", "ZIPCODE"),
    "place": ("CITY",),
    "email": ("EMAIL",),
    "phone": ("TELEPHONENUM",),
    "structured_id": (
        "SOCIALNUM",
        "TAXNUM",
        "IDCARDNUM",
        "PASSPORTNUM",
        "DRIVERLICENSENUM",
        "CREDITCARDNUMBER",
    ),
}
LABEL_TO_GROUP: dict[str, str] = {
    label: group for group, labels in GROUPS.items() for label in labels
}
CONTEXT_ONLY_GROUPS = frozenset({"person", "place"})

MCP_LABEL_TO_GROUP: dict[str, str] = {
    "PERSON": "person",
    "ADDRESS": "street_address",
    "EMAIL": "email",
    "PHONE": "phone",
    "BSN": "structured_id",
    "SSN": "structured_id",
    "TAX_ID": "structured_id",
    "PASSPORT": "structured_id",
    "VAT_ID": "structured_id",
    "CREDIT_CARD": "structured_id",
}


def _load_sample(n_per_language: int, seed: int) -> list[tuple[str, dict]]:
    """Reservoir-sample ``n_per_language`` validation rows per language.

    A single streamed pass over the split, so memory never exceeds
    ``n_per_language`` rows per language regardless of split size.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit(
            "eval/external.py needs the `datasets` package: "
            'pip install -e ".[eval]"'
        )
    rows = load_dataset(DATASET, split="validation", streaming=True, revision=DATASET_REVISION)
    rng = random.Random(seed)
    buckets: dict[str, list[dict]] = {lang: [] for lang in LANGUAGES}
    seen: dict[str, int] = dict.fromkeys(LANGUAGES, 0)
    for row in rows:
        lang = row.get("language")
        if lang not in buckets:
            continue
        seen[lang] += 1
        bucket = buckets[lang]
        if len(bucket) < n_per_language:
            bucket.append(row)
        else:
            j = rng.randrange(seen[lang])
            if j < n_per_language:
                bucket[j] = row
    missing = {lang: len(buckets[lang]) for lang in LANGUAGES if len(buckets[lang]) < n_per_language}
    if missing:
        sys.exit(f"{DATASET} validation split has too few rows for {missing}")
    return [(lang, row) for lang in LANGUAGES for row in buckets[lang]]


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


Alignment = tuple[list[bool], list[tuple[int, int, str]], bool]


def _split_output(output: str) -> tuple[list[str], list[list[str]]]:
    """Literal chunks and, between each pair, the labels of the placeholders there.

    Adjacent placeholders share one gap, so ``len(literals) == len(groups) + 1``.
    """
    parts = _SPLIT_RE.split(output)
    literals = [parts[0]]
    groups: list[list[str]] = []
    for idx in range(1, len(parts), 2):
        label = parts[idx][1:-1]
        if groups and literals[-1] == "":
            groups[-1].append(label)
            literals[-1] = parts[idx + 1]
        else:
            groups.append([label])
            literals.append(parts[idx + 1])
    return literals, groups


def _place_literals(source: str, literals: list[str], from_left: bool) -> list[int] | None:
    """Start offset of each literal chunk in ``source``, or ``None`` if they do not fit.

    The first chunk must be a prefix and the last a suffix of ``source``; each
    middle chunk takes its earliest (``from_left``) or latest position that
    leaves a non-empty gap for the placeholder(s) on both sides.
    """
    if len(literals) == 1:
        return [0] if source == literals[0] else None
    first, last = literals[0], literals[-1]
    if not (source.startswith(first) and source.endswith(last)):
        return None
    starts = [0] * len(literals)
    starts[-1] = len(source) - len(last)
    middle = range(1, len(literals) - 1)
    if from_left:
        pos = len(first)
        for k in middle:
            starts[k] = source.find(literals[k], pos + 1)
            if starts[k] == -1:
                return None
            pos = starts[k] + len(literals[k])
    else:
        pos = starts[-1]
        for k in reversed(middle):
            starts[k] = source.rfind(literals[k], 0, pos - 1)
            if starts[k] == -1:
                return None
            pos = starts[k]
    if any(starts[k] + len(literals[k]) >= starts[k + 1] for k in range(len(literals) - 1)):
        return None
    return starts


def _align_runs(source: str, output: str) -> Alignment | None:
    """(kept, runs, ambiguous) for one scrubbed text, or ``None`` when it cannot be aligned.

    ``kept[i]`` is True when ``source[i]`` survives unchanged in ``output``.
    Each run is a ``(start, end, mcp_label)`` source range that a ``[LABEL]``
    placeholder replaced, ``mcp_label`` without the brackets; adjacent
    placeholders each get a run over their shared range.

    The output's literal chunks are placed on the source in order, each
    after a non-empty gap, with the first chunk a prefix and the last a
    suffix, so a short literal after a placeholder (``.`` after ``[PHONE]``)
    cannot anchor inside the masked value. The runs use the earliest
    placement; ``ambiguous`` is True when the latest placement differs (a
    literal also occurs inside a masked value), which can move a run onto
    the wrong range or label. ``None`` means the literal text does not fit
    the source; the caller counts it and scores none of its gold spans as
    caught. Both placements are linear in the text length.
    """
    literals, groups = _split_output(output)
    starts = _place_literals(source, literals, from_left=True)
    if starts is None:
        return None
    ambiguous = starts != _place_literals(source, literals, from_left=False)
    kept = [True] * len(source)
    runs: list[tuple[int, int, str]] = []
    for k, labels in enumerate(groups):
        start, end = starts[k] + len(literals[k]), starts[k + 1]
        for i in range(start, end):
            kept[i] = False
        runs.extend((start, end, label) for label in labels)
    return kept, runs, ambiguous


def score_sample(sample: list[tuple[str, dict]]) -> dict:
    """Score a ``[(language, row)]`` sample; ``row`` has the dataset's shape.

    A gold span with no alphanumeric characters (an empty or
    punctuation-only annotation) is excluded from every total: it carries no
    signal either way, and counting it as automatically "caught" would
    inflate recall whenever the dataset mislabels a span like that.
    """
    group_totals: dict[str, int] = dict.fromkeys(GROUPS, 0)
    group_leaks: dict[str, int] = dict.fromkeys(GROUPS, 0)
    group_hits: dict[str, int] = dict.fromkeys(GROUPS, 0)
    group_fps: dict[str, int] = dict.fromkeys(GROUPS, 0)
    total_runs = 0
    no_overlap_runs = 0
    unaligned = 0
    ambiguous_texts = 0
    latencies_ms: list[float] = []

    for _lang, row in sample:
        source = row["source_text"]
        gold = row["privacy_mask"]
        t0 = time.perf_counter()
        output = scrub_text(source, languages=list(LANGUAGES))["text"]
        latencies_ms.append((time.perf_counter() - t0) * 1000)

        aligned = _align_runs(source, output)
        if aligned is None:
            unaligned += 1
            kept, runs = [True] * len(source), []
        else:
            kept, runs, ambiguous = aligned
            ambiguous_texts += ambiguous
        gold_alnum = {
            (g["start"], g["end"]): [i for i in range(g["start"], g["end"]) if source[i].isalnum()]
            for g in gold
        }
        gold_spans = [span for span, alnum in gold_alnum.items() if alnum]
        gold_spans_by_group: dict[str, list[tuple[int, int]]] = {g: [] for g in GROUPS}
        for g in gold:
            group = LABEL_TO_GROUP.get(g["label"])
            if group is None:
                continue
            span = (g["start"], g["end"])
            alnum = gold_alnum[span]
            if not alnum:
                continue
            gold_spans_by_group[group].append(span)
            group_totals[group] += 1
            if any(kept[i] for i in alnum):
                group_leaks[group] += 1

        for start, end, mcp_label in runs:
            total_runs += 1
            run = (start, end)
            if not any(_overlaps(run, gs) for gs in gold_spans):
                no_overlap_runs += 1
            group = MCP_LABEL_TO_GROUP.get(mcp_label)
            if group is None:
                continue
            if any(_overlaps(run, gs) for gs in gold_spans_by_group[group]):
                group_hits[group] += 1
            else:
                group_fps[group] += 1

    per_group = {}
    for group in GROUPS:
        total = group_totals[group]
        hits, fps = group_hits[group], group_fps[group]
        per_group[group] = {
            "n": total,
            "recall": round(1 - group_leaks[group] / total, 4) if total else None,
            "precision": round(hits / (hits + fps), 4) if (hits + fps) else None,
        }

    return {
        "dataset": DATASET,
        "revision": DATASET_REVISION,
        "n_texts": len(sample),
        "per_group": per_group,
        "no_gold_overlap_rate": round(no_overlap_runs / total_runs, 4) if total_runs else 0.0,
        "unaligned_texts": unaligned,
        "ambiguous_texts": ambiguous_texts,
        "median_latency_ms": round(statistics.median(latencies_ms), 3) if latencies_ms else 0.0,
    }


def main() -> None:
    os.environ.setdefault("PII_MCP_BACKEND", "python")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=DEFAULT_N, help="texts per language")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--ner", action="store_true", help="also print person/place (context only, not a target)")
    args = ap.parse_args()

    print(f"{DATASET}@{DATASET_REVISION[:12]} (CC BY 4.0, Ai4Privacy / Ai Suisse SA): {DATASET_URL}")
    sample = _load_sample(args.n, args.seed)
    result = score_sample(sample)

    for group, stats in result["per_group"].items():
        if group in CONTEXT_ONLY_GROUPS and not args.ner:
            continue
        suffix = " (context only, not a pii-mcp target)" if group in CONTEXT_ONLY_GROUPS else ""
        print(f"{group}: recall={stats['recall']} precision={stats['precision']} n={stats['n']}{suffix}")
    print(f"masked runs with no gold overlap: {result['no_gold_overlap_rate']}")
    print(f"texts that could not be aligned (scored as leaks): {result['unaligned_texts']}")
    print(f"texts with an ambiguous alignment: {result['ambiguous_texts']}")
    print(f"median latency per text: {result['median_latency_ms']} ms")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
