"""The recall protocol has teeth, not just a document.

`corpus/RECALL-PROTOCOL.md` says a recall number is only publishable if it was
measured on paths whose misses had never been diagnosed in writing before the
fix was designed. A rule with no test is a preference, and this one guards the
single number the product will be judged on, so it is checked here.

Two properties matter more than the plumbing:

1. An empty held-out split reports `n/a`, never `1.000`. Recall over zero paths
   has not been measured, and a perfect score for an empty set is the same
   vacuity the precision guard already refuses.
2. An unassigned label counts as `train`. Defaulting the other way would let a
   forgotten `split:` flatter the publishable number.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus" / "repos.yaml"
PROTOCOL = ROOT / "corpus" / "RECALL-PROTOCOL.md"
PROOF = ROOT / "docs" / "proof-scans.md"


def _precision_module():
    """Load scripts/precision.py, which is a script rather than a package.

    Registered in `sys.modules` before executing: `@dataclass` resolves a
    field's annotations through `sys.modules[cls.__module__]`, so a module that
    is not there yet raises while the decorator runs.
    """
    spec = importlib.util.spec_from_file_location("precision", ROOT / "scripts" / "precision.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["precision"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def Metrics():
    return _precision_module().Metrics


# ---------------------------------------------------------------------------
# The vacuity guard
# ---------------------------------------------------------------------------


def test_an_empty_split_is_not_perfect_recall(Metrics) -> None:
    m = Metrics()
    assert m.recall_for("held-out") is None
    assert m.recall_for("train") is None


def test_a_populated_split_reports_a_real_number(Metrics) -> None:
    """Vacuity guard for the test above: if recall_for always returned None,
    the assertion up there would pass for the wrong reason."""
    m = Metrics()
    m.tp_by_split = {"held-out": 1}
    m.fn_by_split = {"held-out": 3}
    assert m.recall_for("held-out") == 0.25
    assert m.recall_for("train") is None, "splits must not bleed into each other"


def test_pooled_recall_is_not_the_publishable_one(Metrics) -> None:
    """The pooled property still exists - it is printed alongside the split -
    but it is not what a report quotes. Pinned so the distinction survives a
    refactor that might otherwise collapse them."""
    m = Metrics()
    m.tp, m.fn = 2, 8
    m.tp_by_split, m.fn_by_split = {"train": 2}, {"train": 8}
    assert m.recall == 0.2
    assert m.recall_for("held-out") is None


# ---------------------------------------------------------------------------
# The corpus obeys its own protocol
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def corpus() -> dict:
    return yaml.safe_load(CORPUS.read_text(encoding="utf-8"))


def test_every_labelled_repo_declares_a_split(corpus: dict) -> None:
    missing = [r["name"] for r in corpus["repos"] if r.get("expect") and not r.get("split")]
    assert not missing, (
        f"these carry recall labels with no `split:` - see corpus/RECALL-PROTOCOL.md: {missing}"
    )


def test_splits_use_only_the_two_defined_values(corpus: dict) -> None:
    allowed = {"train", "held-out"}
    bad = {
        r["name"]: r["split"]
        for r in corpus["repos"]
        if r.get("split") and r["split"] not in allowed
    }
    assert not bad, f"split must be one of {allowed}: {bad}"


def test_the_existing_paths_are_all_train(corpus: dict) -> None:
    """Their misses are diagnosed, repo by repo, in docs/proof-scans.md. That
    text is the specification the engine fixes are written against, so none of
    them can ever serve as held-out evidence. This test is what stops a future
    change quietly reclassifying one to improve the headline.
    """
    held = [r["name"] for r in corpus["repos"] if r.get("expect") and r.get("split") == "held-out"]
    diagnosed = PROOF.read_text(encoding="utf-8")
    leaked = [name for name in held if name.split("-")[0] in diagnosed]
    assert not leaked, (
        "these are held-out but their misses are already explained in "
        f"docs/proof-scans.md, so the number they produce is not evidence: {leaked}"
    )


def _repo_blocks(raw: str) -> dict[str, str]:
    """Split the raw YAML into per-repo text blocks, comments included.

    The parsed document is no use here: `yaml.safe_load` discards comments, and
    the comments are exactly where a diagnosis would be written.
    """
    blocks: dict[str, str] = {}
    name: str | None = None
    buf: list[str] = []
    for line in raw.splitlines():
        if line.strip().startswith("- name:"):
            if name:
                blocks[name] = "\n".join(buf)
            name = line.split("- name:", 1)[1].strip()
            buf = [line]
        elif name:
            buf.append(line)
    if name:
        blocks[name] = "\n".join(buf)
    return blocks


# Words that only appear when someone is explaining a miss rather than locating
# one. Deliberately narrow: this must not fire on a normal descriptive comment.
_DIAGNOSIS_MARKERS = (
    "missed:",
    "not recognized",
    "not recognised",
    "not modeled",
    "not modelled",
    "why it is missed",
    "engine misses",
    "would need",
)


def test_held_out_labels_carry_no_diagnosis(corpus: dict) -> None:
    """Rule 2 of the protocol, enforced.

    A held-out label may say where a vulnerability is. The sentence explaining
    why the engine misses it is the specification for the fix, so writing it
    converts the path to training data. The existing train labels contain
    exactly such sentences, which is correct for them and disqualifying for a
    held-out entry.
    """
    raw = CORPUS.read_text(encoding="utf-8")
    blocks = _repo_blocks(raw)
    held = [r["name"] for r in corpus["repos"] if r.get("split") == "held-out"]

    offenders: list[str] = []
    for name in held:
        text = blocks.get(name, "").lower()
        hits = [m for m in _DIAGNOSIS_MARKERS if m in text]
        if hits:
            offenders.append(f"{name}: {hits}")
    assert not offenders, (
        "held-out labels must carry location, never diagnosis - that sentence "
        "becomes the spec for the fix. Retire the path to `train` first, or "
        f"delete the explanation: {offenders}"
    )


def test_the_diagnosis_detector_actually_fires(corpus: dict) -> None:
    """Vacuity guard for the test above.

    If `_DIAGNOSIS_MARKERS` matched nothing in this file, the held-out check
    would pass no matter what anyone wrote. The train labels are known to
    contain diagnoses, so at least one of them must trip the detector.
    """
    blocks = _repo_blocks(CORPUS.read_text(encoding="utf-8"))
    train = [r["name"] for r in corpus["repos"] if r.get("split") == "train"]
    tripped = [
        name for name in train if any(m in blocks.get(name, "").lower() for m in _DIAGNOSIS_MARKERS)
    ]
    assert tripped, (
        "no train label trips the diagnosis detector, so it would not catch a "
        "held-out one either - the markers need widening"
    )


def test_the_split_assignment_is_recorded(corpus: dict) -> None:
    """Rule 1: the assignment must be reproducible, not remembered.

    A seeded shuffle recorded in the manifest is auditable after the fact; an
    assignment someone made by hand while looking at the repos is not.
    """
    meta = corpus.get("split_assignment")
    if not any(r.get("split") == "held-out" for r in corpus["repos"]):
        pytest.skip("nothing is held out yet; nothing to audit")
    assert meta, (
        "repos.yaml must carry a `split_assignment:` block recording how the "
        "held-out set was chosen (seed, method, date) - see RECALL-PROTOCOL.md"
    )
    for key in ("seed", "method", "assigned"):
        assert key in meta, f"split_assignment is missing `{key}`"


def test_an_unassigned_label_defaults_to_train() -> None:
    """A source-level check, deliberately, and worth saying why.

    `test_every_labelled_repo_declares_a_split` makes the default unreachable
    today, so no behavioural test can observe it - mutation confirmed that
    flipping the default to `held-out` breaks nothing. But the direction is the
    safe-by-default choice: a forgotten `split:` must land in the half that is
    not publishable, never in the half that is. Pinning the literal keeps that
    decision from being reversed by someone who reads it as arbitrary.
    """
    source = (ROOT / "scripts" / "precision.py").read_text(encoding="utf-8")
    assert 'entry.get("split", "train")' in source, (
        "an unassigned label must default to `train`: defaulting to `held-out` "
        "would let a forgotten split flatter the publishable number"
    )


def test_the_protocol_document_exists_and_states_the_rule() -> None:
    """The tests above enforce the mechanism; the reasoning has to be findable
    or the next person reads the plumbing and infers the wrong rule."""
    text = PROTOCOL.read_text(encoding="utf-8")
    assert "never been diagnosed in writing" in text
    assert "held-out" in text and "train" in text
    assert "one-way door" in text.lower(), "the no-reassignment rule must be stated"
