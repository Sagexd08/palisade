"""The launch surfaces may not publish precision without recall.

This is the rule that took three measurements to earn. Precision 1.000 over
40,466 files is true and, quoted alone, it is an advertisement for a scanner
that finds almost nothing: a tool that reports nothing has perfect precision for
free. Held-out recall is 0.000 over 45 independent observations, and a reader
who sees one number without the other has been misled by omission.

Prose has no tests, which is how ten places came to quote a recall figure
measured on the engine's own training material for months. So the rule is
mechanical here: any user-facing surface that states the precision claim must
state the held-out figure too, with its denominator.

Scoped to the surfaces a user or a model actually reads. The CHANGELOG is
excluded: it is a record of what was true at each release, and rewriting history
to satisfy a present-day rule would be the opposite of honest.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

SURFACES = [
    "README.md",
    "llms.txt",
    "website/index.html",
    "docs/PRD.md",
    "docs/roadmap.md",
    "docs/proof-scans.md",
    "docs/typesafe-integration.md",
    "docs-site/src/content/docs/roadmap.md",
    "docs-site/src/content/docs/proof-scans.md",
]

# The precision claim in any of the spellings the surfaces actually use.
_PRECISION = re.compile(r"precision[^.\n]{0,40}1\.000|zero false positives|0 false positives", re.I)
# The held-out figure, and its denominator - a bare "0.000" would let someone
# satisfy this rule while leaving the reader to assume n=2.
_HELD_OUT = re.compile(r"held-out", re.I)
_DENOMINATOR = re.compile(r"\b45\b|\b98\b")


def _files() -> list[Path]:
    return [ROOT / s for s in SURFACES if (ROOT / s).is_file()]


def test_the_surfaces_exist() -> None:
    """Vacuity guard. If the paths drift, every test below passes on an empty
    list and the rule silently stops applying."""
    found = _files()
    assert len(found) >= 8, f"only found {[str(f) for f in found]}"


@pytest.mark.parametrize("rel", SURFACES)
def test_precision_is_never_published_alone(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    text = path.read_text(encoding="utf-8")
    if not _PRECISION.search(text):
        return  # a surface that makes no precision claim owes nothing
    assert _HELD_OUT.search(text), (
        f"{rel} states the precision claim and never mentions held-out recall. "
        "A scanner that reports nothing has perfect precision for free, so the "
        "two numbers are published together or not at all."
    )
    assert _DENOMINATOR.search(text), (
        f"{rel} mentions held-out recall without its denominator. 0.000 over 45 "
        "independent observations is a far stronger statement than 0.000 over "
        "2, and a bare figure lets a reader assume either."
    )


def test_the_detector_claim_does_not_overreach(rel: str = "README.md") -> None:
    """The narrow claim, pinned where a reader meets it first.

    Three engine passes each moved held-out recall by zero paths, so a claim to
    find the agent-framework shape is one a first scan would embarrass. The
    README has to say what is not covered, in the open.
    """
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert "does not currently catch" in text or "does not catch" in text, (
        "the README must state the shape Palisade does NOT catch - it is the "
        "difference between a limit a user reads and a limit a user discovers"
    )
    assert "agent-framework" in text or "agent framework" in text, (
        "the uncovered shape must be named, not gestured at"
    )


def test_the_direction_of_error_is_published() -> None:
    """Ground truth is known-incomplete and the bias runs one way, so the
    recall figure is generous rather than conservative. A reader who later
    finds an unlabelled sibling should find that we said so first."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "known-incomplete" in text or "overestimate" in text, (
        "the README must carry the direction of the ground-truth error"
    )


# ---------------------------------------------------------------------------
# The judged layer is advisory and uncalibrated, and must say so
# ---------------------------------------------------------------------------
#
# The recall pair is not the only number a reader can over-read. `audit` and
# `review` ship in 0.7.0 with their calibration still a 10-case seed corpus
# (n=4-6 per signal) - not a benchmark result - and the judged layer is the part
# of this release most likely to be read as "the AI decides whether you are
# safe". It is the same failure as quoting precision alone: a number that sounds
# like evidence, presented without the thing that makes it weak.
#
# Substance, not vocabulary. Nothing requires the word "uncalibrated"; a surface
# that says "preliminary, measured on a seed corpus, not a benchmark result"
# has told the reader more than the word would.

# The FEATURE, not the English words. A first draft matched `\baudit\b` and
# `\breview\b`, which fired on "a 2026-09-22 audit of the clean repos" and on
# "review, then either fix or baseline" - ordinary prose about auditing and
# reviewing, nothing to do with the judged layer. A guard that cries wolf on
# plain English gets widened until it means nothing.
_JUDGED = re.compile(
    r"palisade-sec\s+(audit|review)|`audit`|`review`|judgment layer|judged (layer|check|signal)",
    re.I,
)
_ADVISORY = re.compile(r"advisory", re.I)
_UNCALIBRATED = re.compile(
    r"uncalibrated|not calibrated|preliminary|seed corpus|seed-corpus|not a benchmark result",
    re.I,
)


@pytest.mark.parametrize("rel", SURFACES)
def test_the_judged_layer_is_labelled_advisory_and_uncalibrated(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} not present")
    text = path.read_text(encoding="utf-8")
    if not _JUDGED.search(text):
        return  # a surface that never mentions the judged layer owes nothing
    assert _ADVISORY.search(text), (
        f"{rel} describes the judged layer and never calls it advisory. It is "
        "the part of this release most likely to be read as the tool deciding "
        "whether you are safe."
    )
    assert _UNCALIBRATED.search(text), (
        f"{rel} describes the judged layer without saying its calibration is "
        "preliminary. The signal is measured on a 10-case seed corpus, not a "
        "benchmark, and a reader cannot know that from the surface alone."
    )


def test_the_judged_caveat_guard_is_not_vacuous() -> None:
    """The regexes have to actually fire, or every assertion above passes on a
    surface that says nothing at all."""
    assert _JUDGED.search("run palisade-sec audit .")
    assert not _JUDGED.search("a 2026-09-22 audit of the clean repos found 7 paths")
    assert not _JUDGED.search("advisory severity: review, then fix or baseline")
    assert not _JUDGED.search("a precise static detector for one shape")
    assert _ADVISORY.search("the judged layer stays advisory")
    assert _UNCALIBRATED.search("calibration is preliminary")
    assert not _UNCALIBRATED.search("precision 1.000 with zero false positives")
