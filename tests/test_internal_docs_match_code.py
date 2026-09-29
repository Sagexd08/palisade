"""`docs/typesafe-integration.md` is the judgment layer's spec, and it drifted.

It claimed "1 of ~9 checks + 5 taint rules" for months after the second check
and the sixth rule shipped, listed a 4-module layout that had grown to 13, and
told readers to install an extra (`[semantic]`) and set a key
(`TYPESAFE_API_KEY`) that are no longer the only ones. Nothing caught it,
because prose has no tests.

These are the few claims in that document that are countable from the code.
Pinning only those keeps the test honest: a spec is allowed to describe things
that do not exist yet, so this asserts the *shipped* counts are stated
correctly, not that every row is built.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "typesafe-integration.md"
SRC = ROOT / "src" / "palisade_sec"


@pytest.fixture(scope="module")
def doc() -> str:
    """The prose as one long line. Markdown is hard-wrapped at 80 columns, so a
    phrase this test cares about is routinely split across a newline - the same
    trap that made the CLI output tests brittle."""
    return " ".join(DOC.read_text(encoding="utf-8").split())


def _taint_rule_count() -> int:
    """The 5 YAML rules plus PI-AGENT-HANDOFF, which lives in code."""
    yaml_rules = {
        m.group(1)
        for path in (SRC / "rules").glob("*.yaml")
        for m in [re.search(r"^id:\s*(\S+)", path.read_text(encoding="utf-8"), re.M)]
        if m
    }
    agents = (SRC / "semantic" / "agents" / "findings.py").read_text(encoding="utf-8")
    code_rules = set(re.findall(r'^RULE_ID\s*=\s*"([^"]+)"', agents, re.M))
    return len(yaml_rules | code_rules)


def _shipped_check_count() -> int:
    """Judged checks `audit` actually runs, counted from its orchestrator."""
    audit = (SRC / "semantic" / "audit.py").read_text(encoding="utf-8")
    return len(re.findall(r"^def audit_(\w+)\(", audit, re.M))


def test_the_counters_are_not_vacuous() -> None:
    """If these helpers silently returned 0, every assertion below would pass
    for the wrong reason."""
    assert _taint_rule_count() == 6, _taint_rule_count()
    assert _shipped_check_count() == 2, _shipped_check_count()


def test_doc_states_the_real_taint_rule_count(doc: str) -> None:
    n = _taint_rule_count()
    assert f"**{n}** deterministic taint" in doc or f"+ **{n}** taint rules" in doc, (
        f"there are {n} taint rules; the doc does not say so"
    )
    assert "5 taint rules" not in doc, "stale count: there are 6 taint rules"


def test_doc_states_the_real_shipped_check_count(doc: str) -> None:
    n = _shipped_check_count()
    assert f"**{n} of ~9**" in doc, f"`audit` runs {n} checks; the doc does not say so"
    assert "1 of ~9" not in doc, "stale count: a second judged check shipped in v0.5.0"


def test_doc_names_the_extra_that_actually_exists(doc: str) -> None:
    """`[semantic]` is only an alias now; telling a reader to install it as *the*
    name sends them to the wrong place in every other doc."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "\njudge = [" in pyproject, "the [judge] extra is gone; this test needs updating"
    assert "`[judge]`" in doc, "the doc must name the [judge] extra"
    assert "pip install 'palisade-sec[judge]'" in doc


def test_doc_mentions_connect_llm(doc: str) -> None:
    """0.6.0 made `connect llm` the way a key gets set. A spec that only
    mentions env vars and .env describes the previous release."""
    assert "palisade-sec connect llm" in doc


@pytest.mark.parametrize(
    "backend",
    ["typesafe", "anthropic", "openai_compatible"],
)
def test_doc_covers_every_shipped_backend(doc: str, backend: str) -> None:
    assert (SRC / "judge" / f"{backend}.py").is_file(), f"{backend} backend is gone"
    assert backend in doc, f"{backend} backend ships but the doc never names it"


def test_doc_matches_whether_policy_files_load(doc: str) -> None:
    """This test has now run in both directions.

    While `policy.py` had no reader, it asserted the doc said so - the YAML in
    §5 was the gap most likely to mislead someone adopting the spec. The reader
    landed, so it now asserts the opposite: the doc must not still carry the
    warning, and must document the trust boundary on `criteria`, which is the
    part of the feature that is security-relevant rather than cosmetic.
    """
    policy = (SRC / "semantic" / "policy.py").read_text(encoding="utf-8")
    loads_files = "def load_policy" in policy
    if not loads_files:
        assert "does not load yet" in doc, (
            "policy.py has no file reader; the doc must not imply the YAML works"
        )
        return
    assert "does not load yet" not in doc, (
        "`load_policy` exists now; the doc still says policy files do not load"
    )
    assert "--policy" in doc, "the doc must name the flag that loads a policy"
    assert "criteria" in doc and "judge" in doc, (
        "the doc must explain why `criteria` from a discovered file is refused - "
        "it is prompt text reaching the judge"
    )


def test_doc_carries_the_recall_number(doc: str) -> None:
    """The layer's honest weak point, and there are now two numbers.

    A capability doc that lists 9 checks and omits recall oversells. Quoting
    only the train figure oversells in a subtler way: that half's misses are all
    explained in docs/proof-scans.md, so the engine is built against them. The
    held-out figure is the one a reader should judge the layer on, so the doc
    has to carry it - with its n, because 0.000 over 6 paths is a weak estimate
    and reads as a much stronger claim without the sample size.
    """
    assert "recall 0.200" in doc or "precision 1.000, recall 0.200" in doc
    assert "held-out" in doc, "the doc quotes only the train recall"
    assert "0.000" in doc, "the held-out recall number is missing"
    assert "n=6" in doc, "the held-out number must carry its sample size"
