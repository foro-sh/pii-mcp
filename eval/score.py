"""Score the Python detectors: one loss number plus pass/fail gates.

    python eval/score.py                  # dev split, all gates
    python eval/score.py --quick          # dev split, skip pytest/perf gates
    python eval/score.py --save-baseline  # record perf baseline for this machine
    PII_EVAL_HOLDOUT_SEED=<secret> PII_EVAL_HOLDOUT_TEMPLATES=<file> \
        python eval/score.py --split holdout

loss = 3 * leak_rate + fp_rate + 0.5 * overreach_rate   (lower is better)

- leak: any alphanumeric of the PII value survives in the output
- fp: a clean sample is changed at all
- overreach: the surrounding template is damaged around a PII value

The last line printed is machine-readable JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

os.environ["PII_MCP_BACKEND"] = "python"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

from generators import AMBIGUOUS, CLEAN, PII, TEMPLATES  # noqa: E402

from pii_mcp import scrub_text  # noqa: E402

DEV_SEED = 0
PER_GENERATOR = 300
BASELINE = ROOT / "eval" / ".baseline.json"
PERF_BUDGET = 1.15  # allowed slowdown vs baseline
REDOS_LIMIT_S = 2.0
PLACEHOLDER_RE = re.compile(
    r"\[(?:EMAIL|IBAN|CREDIT_CARD|BIC|MAC|IMEI|IP|LOCATION|BSN|SSN|TAX_ID|VAT_ID"
    r"|PASSPORT|PHONE|PERSON|ADDRESS|LICENSE_PLATE)\]"
)
DEFAULT_LANGS = ["en", "nl"]


def fill(template: str, value: str) -> str:
    return template.replace("{}", value)


def load_private_templates(path: str) -> list[str]:
    """Holdout contexts from a file outside the repo, one per line.

    ``{}`` marks the value (exactly once); ``\\n`` / ``\\t`` are decoded;
    blank lines and ``#`` comments are skipped. Errors cite line numbers only,
    so the output never reveals the templates.
    """
    templates: list[tuple[int, str]] = []
    for lineno, raw in enumerate(Path(path).read_text().splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        templates.append((lineno, raw.replace("\\n", "\n").replace("\\t", "\t")))
    bad = [n for n, t in templates if t.count("{}") != 1]
    if bad:
        sys.exit(f"holdout templates: lines {bad} need exactly one {{}}")
    # A template the detectors alter on its own would score as overreach.
    noisy = [n for n, t in templates if scrub_text(fill(t, ""), languages=["en", "nl", "de"])["text"] != fill(t, "")]
    if noisy:
        sys.exit(f"holdout templates: lines {noisy} are changed by the scrubber without a value")
    if len(templates) < 5:
        sys.exit("holdout templates: need at least 5")
    return [t for _, t in templates]


def build(seed: int, templates: list[str] = TEMPLATES) -> tuple[list[tuple], list[tuple], list[tuple]]:
    r = random.Random(seed)
    pii = [
        (cat, gen.__name__, r.choice(templates), gen(r), sorted(set(DEFAULT_LANGS) | set(langs)))
        for cat, gen, langs in PII
        for _ in range(PER_GENERATOR)
    ]
    clean = [(name, fill(r.choice(templates), gen(r))) for name, gen in CLEAN for _ in range(PER_GENERATOR)]
    ambiguous = [(name, fill(r.choice(templates), gen(r))) for name, gen in AMBIGUOUS for _ in range(PER_GENERATOR)]
    return pii, clean, ambiguous


def judge_pii(template: str, value: str, langs: list[str]) -> tuple[bool, bool, str]:
    """(leaked, overreach, output)."""
    out = scrub_text(fill(template, value), languages=langs)["text"]
    marked = PLACEHOLDER_RE.sub("\x00", out)
    pre, suf = template.split("{}")
    if marked.startswith(pre) and marked.endswith(suf) and len(marked) >= len(pre) + len(suf):
        mid = marked[len(pre) : len(marked) - len(suf)]
        return any(ch.isalnum() for ch in mid), False, out
    # Template damaged: fall back to "does any 3+ char chunk of the value survive".
    chunks = [c for c in re.split(r"[^0-9A-Za-z]+", value) if len(c) >= 3]
    return any(c in marked for c in chunks), True, out


def score(seed: int, show: int, templates: list[str] = TEMPLATES) -> dict:
    pii, clean, ambiguous = build(seed, templates)
    leaks: Counter[str] = Counter()
    overreach: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    examples: list[str] = []
    for cat, gen, template, value, langs in pii:
        key = f"{cat}/{gen}"
        totals[key] += 1
        leaked, damaged, out = judge_pii(template, value, langs)
        leaks[key] += leaked
        overreach[key] += damaged
        if (leaked or damaged) and len(examples) < show:
            examples.append(f"{'LEAK' if leaked else 'OVER'} {key}: {fill(template, value)!r} -> {out!r}")
    fps: Counter[str] = Counter()
    for name, text in clean:
        out = scrub_text(text, languages=DEFAULT_LANGS)["text"]
        if out != text:
            fps[name] += 1
            if len(examples) < show * 2:
                examples.append(f"FP   {name}: {text!r} -> {out!r}")
    amb: Counter[str] = Counter(
        name for name, text in ambiguous if scrub_text(text, languages=DEFAULT_LANGS)["text"] != text
    )
    n_pii, n_clean = len(pii), len(clean)
    leak_rate = sum(leaks.values()) / n_pii
    over_rate = sum(overreach.values()) / n_pii
    fp_rate = sum(fps.values()) / n_clean
    return {
        "loss": round(3 * leak_rate + fp_rate + 0.5 * over_rate, 5),
        "leak_rate": round(leak_rate, 5),
        "fp_rate": round(fp_rate, 5),
        "overreach_rate": round(over_rate, 5),
        "leaks": {k: round(v / totals[k], 3) for k, v in leaks.most_common() if v},
        "overreach": {k: round(v / totals[k], 3) for k, v in overreach.most_common() if v},
        "fps": {k: round(v / PER_GENERATOR, 3) for k, v in fps.most_common() if v},
        "ambiguous_masked": {k: round(v / PER_GENERATOR, 3) for k, v in amb.most_common()},
        "examples": examples,
    }


# --- gates -----------------------------------------------------------------

REDOS_INPUTS = [
    "1" * 200_000,
    "1 " * 100_000,
    "1." * 100_000,
    "a:" * 100_000,
    "ab" * 100_000 + "@",
    "a@" * 100_000,
    "a." * 100_000 + "@",
    "0-" * 100_000,
    "NL91" * 50_000,
    ("aa:" * 5 + "zz ") * 20_000,
    "+" + "1 (" * 60_000,
    "12.3456, " * 40_000,
]


def gate_redos() -> str | None:
    """Each adversarial input must scrub within REDOS_LIMIT_S.

    Runs in a subprocess: a catastrophic regex holds the GIL, so an in-process
    thread timeout would never fire.
    """
    code = "import sys; from pii_mcp import scrub_text; scrub_text(sys.stdin.read(), languages=['en', 'nl', 'de'])"
    env = {**os.environ, "PII_MCP_BACKEND": "python", "PYTHONPATH": str(ROOT / "src")}
    for text in REDOS_INPUTS:
        try:
            subprocess.run([sys.executable, "-c", code], input=text, text=True, env=env, timeout=REDOS_LIMIT_S, check=True)
        except subprocess.TimeoutExpired:
            return f"input {text[:12]!r}... exceeded {REDOS_LIMIT_S}s"
        except subprocess.CalledProcessError as exc:
            return f"input {text[:12]!r}... crashed ({exc.returncode})"
    return None


def perf_seconds() -> float:
    pii, clean, _ = build(1234)
    texts = [fill(t, v) for _, _, t, v, _ in pii[::5]] + [t for _, t in clean[::5]]
    blob = "\n".join(texts) * 3
    best = float("inf")
    for _ in range(5):
        t0 = time.perf_counter()
        scrub_text(blob, languages=["en", "nl", "de"])
        best = min(best, time.perf_counter() - t0)
    return best


def gate_perf() -> str | None:
    if not BASELINE.exists():
        return None
    base = json.loads(BASELINE.read_text())["perf_s"]
    now = perf_seconds()
    if now > base * PERF_BUDGET:
        return f"{now * 1000:.0f} ms > {PERF_BUDGET}x baseline {base * 1000:.0f} ms"
    return None


def gate_pytest() -> str | None:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "tests"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PII_MCP_BACKEND": "python"},
    )
    if proc.returncode != 0:
        return proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "pytest failed"
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "holdout"], default="dev")
    ap.add_argument("--quick", action="store_true", help="skip pytest and perf gates")
    ap.add_argument("--save-baseline", action="store_true")
    ap.add_argument("--show", type=int, default=15, help="failure examples to print")
    args = ap.parse_args()

    if args.save_baseline:
        BASELINE.write_text(json.dumps({"perf_s": perf_seconds()}))
        print(f"baseline saved to {BASELINE}")
        return

    if args.split == "holdout":
        secret = os.environ.get("PII_EVAL_HOLDOUT_SEED")
        if not secret:
            sys.exit("holdout needs PII_EVAL_HOLDOUT_SEED")
        seed = int.from_bytes(secret.encode(), "big") % (2**31)
        path = os.environ.get("PII_EVAL_HOLDOUT_TEMPLATES")
        if not path:
            sys.exit("holdout needs PII_EVAL_HOLDOUT_TEMPLATES (a template file outside the repo)")
        templates = load_private_templates(path)
    else:
        seed, templates = DEV_SEED, TEMPLATES

    result = score(seed, 0 if args.split == "holdout" else args.show, templates)
    gates = {"redos": gate_redos()}
    if not args.quick:
        gates["pytest"] = gate_pytest()
        gates["perf"] = gate_perf()
    result["gates_failed"] = {k: v for k, v in gates.items() if v}
    result["ok"] = not result["gates_failed"]

    for line in result.pop("examples"):
        print(line)
    for key in ("leaks", "overreach", "fps", "ambiguous_masked"):
        if result[key]:
            print(f"{key}: {result[key]}")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
