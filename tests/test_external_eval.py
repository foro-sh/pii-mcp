"""Unit tests for the ai4privacy scoring logic in eval/external.py.

No network and no ``datasets`` package needed: rows are built by hand in the
same shape ``datasets`` would hand back (``source_text`` + ``privacy_mask``),
so these exercise the character-level diff/grouping logic against the real
Python detectors without touching the Hugging Face Hub.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

import external  # noqa: E402
from external import _diff_runs, _overlaps, score_sample  # noqa: E402


def _row(text: str, labels: list[tuple[str, str]]) -> tuple[str, dict]:
    """Build a dataset-shaped row; ``labels`` is ``[(gold_label, value)]``.

    Each ``value`` must appear exactly once in ``text``.
    """
    mask = []
    for label, value in labels:
        start = text.index(value)
        mask.append({"label": label, "value": value, "start": start, "end": start + len(value)})
    return ("en", {"source_text": text, "privacy_mask": mask})


def test_importing_the_eval_modules_leaves_the_backend_alone() -> None:
    env = {k: v for k, v in os.environ.items() if k != "PII_MCP_BACKEND"}
    code = (
        "import os, sys; sys.path.insert(0, 'eval'); import external, score; "
        "print(os.environ.get('PII_MCP_BACKEND'))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "None"


def test_overlaps() -> None:
    assert _overlaps((0, 5), (3, 8))
    assert not _overlaps((0, 5), (5, 8))
    assert not _overlaps((0, 5), (6, 8))


def test_diff_runs_marks_only_the_masked_span() -> None:
    source = "Call 0611222333 now"
    output = "Call [PHONE] now"
    kept, runs = _diff_runs(source, output)
    masked_start, masked_end = source.index("0611222333"), source.index("0611222333") + len("0611222333")
    assert not any(kept[masked_start:masked_end])
    assert all(kept[:masked_start])
    assert all(kept[masked_end:])
    assert runs == [(masked_start, masked_end, "PHONE")]


def test_diff_runs_keeps_both_labels_for_adjacent_placeholders() -> None:
    """Two PII values back to back share a span; neither label is dropped."""
    source = "Janedoe0612345678bye"
    output = "[PERSON][PHONE]bye"
    kept, runs = _diff_runs(source, output)
    masked_end = len("Janedoe0612345678")
    assert not any(kept[:masked_end])
    assert all(kept[masked_end:])
    assert runs == [(0, masked_end, "PERSON"), (0, masked_end, "PHONE")]


def test_diff_runs_does_not_anchor_inside_the_masked_value() -> None:
    source = "Call me at 089.2898-5006."
    kept, runs = _diff_runs(source, "Call me at [PHONE].")
    start = source.index("089")
    assert runs == [(start, len(source) - 1, "PHONE")]
    assert not any(kept[start:-1])
    assert kept[-1]


def test_diff_runs_returns_none_when_literals_do_not_fit() -> None:
    assert _diff_runs("a 0612345678 b SECRET", "a [PHONE] b X") is None


def test_unaligned_text_scores_its_gold_spans_as_leaked(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = [_row("ticket 111222333 open", [("SOCIALNUM", "111222333")])]
    monkeypatch.setattr(external, "scrub_text", lambda text, **_: {"text": "ticket [BSN] changed"})
    result = score_sample(sample)
    assert result["unaligned_texts"] == 1
    assert result["per_group"]["structured_id"]["recall"] == 0.0


def test_phone_recall_counts_a_value_followed_by_a_period() -> None:
    sample = [_row("Bel me op +31 6 12345678.", [("TELEPHONENUM", "+31 6 12345678")])]
    result = score_sample(sample)
    assert result["per_group"]["phone"] == {"n": 1, "recall": 1.0, "precision": 1.0}


def test_precision_counts_a_mapped_run_outside_its_group() -> None:
    sample = [_row(
        "BSN 111222333, ref 222333444",
        [("TELEPHONENUM", "111222333")],
    )]
    result = score_sample(sample)
    assert result["per_group"]["structured_id"]["precision"] == 0.0


def test_empty_gold_span_is_excluded_not_auto_caught() -> None:
    """A zero-width or punctuation-only annotation carries no signal."""
    sample = [("en", {
        "source_text": "ticket --- open",
        "privacy_mask": [{"label": "SOCIALNUM", "value": "---", "start": 7, "end": 10}],
    })]
    result = score_sample(sample)
    assert result["per_group"]["structured_id"] == {"n": 0, "recall": None, "precision": None}


def test_recall_counts_a_caught_structured_id() -> None:
    sample = [_row("BSN 111222333 on file", [("SOCIALNUM", "111222333")])]
    result = score_sample(sample)
    assert result["per_group"]["structured_id"] == {"n": 1, "recall": 1.0, "precision": 1.0}


def test_recall_counts_a_leaked_structured_id() -> None:
    """A bad-checksum BSN-shaped value is gold-labeled but never masked."""
    sample = [_row("ticket 123456789 open", [("SOCIALNUM", "123456789")])]
    result = score_sample(sample)
    assert result["per_group"]["structured_id"]["recall"] == 0.0


def test_place_recall_is_zero_person_and_place_are_not_a_target() -> None:
    sample = [_row("ship to 221B Baker Street, London", [
        ("BUILDINGNUM", "221B"),
        ("STREET", "Baker Street"),
        ("CITY", "London"),
    ])]
    result = score_sample(sample)
    assert result["per_group"]["street_address"] == {"n": 2, "recall": 1.0, "precision": 1.0}
    assert result["per_group"]["place"]["recall"] == 0.0
    assert result["per_group"]["place"]["precision"] is None


def test_masked_run_with_no_gold_span_counts_as_no_overlap() -> None:
    """An email pii-mcp catches, but the dataset never labeled, is not a gold miss."""
    sample = [_row(
        "Contact ada@example.com, call +31 6 12345678 today",
        [("TELEPHONENUM", "+31 6 12345678")],
    )]
    result = score_sample(sample)
    assert result["no_gold_overlap_rate"] == 0.5
    assert result["per_group"]["phone"] == {"n": 1, "recall": 1.0, "precision": 1.0}
