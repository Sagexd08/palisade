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
import re
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

    Matching is on the full repo name, plus the base name when the suffix is one
    of the corpus's own version markers (`vanna-cve` and `vanna-later` are both
    "vanna" in the prose), and always on a separator boundary.

    Both refinements came from false alarms, which is worth recording: a plain
    substring match caught `agno` inside the word "di-agno-sed", and splitting
    on the first hyphen caught `pydantic-ai` on a sentence about pydantic body
    params. Each would have disqualified a clean held-out repo over a
    coincidence of spelling.

    The boundary treats `_` as a separator as well as punctuation, so a genuine
    mention inside `langchain_community` still matches while `diagnosed` does
    not. This check is a tripwire, not an oracle: when it fires, read the
    surrounding sentence before retiring a repo.
    """
    held = [r["name"] for r in corpus["repos"] if r.get("expect") and r.get("split") == "held-out"]
    diagnosed = PROOF.read_text(encoding="utf-8")
    markers = ("-cve", "-later", "-patched")

    def _aliases(name: str) -> list[str]:
        for suffix in markers:
            if name.endswith(suffix):
                return [name, name[: -len(suffix)]]
        return [name]

    def _mentioned(name: str) -> bool:
        return bool(re.search(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", diagnosed))

    leaked = [name for name in held if any(_mentioned(a) for a in _aliases(name))]
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


def _shipped_rule_ids() -> set[str]:
    yaml_ids = {
        m.group(1)
        for path in (ROOT / "src" / "palisade_sec" / "rules").glob("*.yaml")
        for m in [re.search(r"^id:\s*(\S+)", path.read_text(encoding="utf-8"), re.M)]
        if m
    }
    agents = (ROOT / "src" / "palisade_sec" / "semantic" / "agents" / "findings.py").read_text(
        encoding="utf-8"
    )
    return yaml_ids | set(re.findall(r'^RULE_ID\s*=\s*"([^"]+)"', agents, re.M))


def test_every_label_names_a_shipped_rule(corpus: dict) -> None:
    """So that labelling never needs to read the rules' sink patterns.

    Assigning a `rule:` id used to mean opening the rule files to see which one
    covered a sink - which is how engine internals leak into a pass that is
    supposed to be blind to them (see the disclosure in RECALL-PROTOCOL.md). A
    labeller needs the id to be *valid*; the capability category is readable
    off the sink line itself. This test supplies the validity check so nobody
    has to go looking.
    """
    shipped = _shipped_rule_ids()
    assert len(shipped) >= 6, f"rule discovery is broken, found {shipped}"
    bad = [
        f"{r['name']}:{e['file']}:{e['line']} -> {e['rule']}"
        for r in corpus["repos"]
        for e in (r.get("expect") or [])
        if e.get("rule") and e["rule"] not in shipped
    ]
    assert not bad, f"labels naming a rule that does not ship (valid: {sorted(shipped)}): {bad}"


def test_held_out_labels_record_a_mitigation(corpus: dict) -> None:
    """A mitigated path still counts as a miss, but it ranks lower, and the
    ranking is only possible if the label says so. This is a fact about the
    repo's own defences, not about the engine, so it is safe for a held-out
    entry to carry - unlike the reason it was missed."""
    missing = [
        f"{r['name']}:{e['file']}:{e['line']}"
        for r in corpus["repos"]
        if r.get("split") == "held-out"
        for e in (r.get("expect") or [])
        if not e.get("mitigation")
    ]
    assert not missing, f"held-out labels must record the repo's mitigation (or 'none'): {missing}"


def test_labelled_repos_pin_a_ref(corpus: dict) -> None:
    """A label is a claim about a line at a commit. Tracking a default branch
    means the next fetch can move the line under the label, turning a drift
    into a silent mis-score."""
    floating = [r["name"] for r in corpus["repos"] if (r.get("expect") or []) and not r.get("ref")]
    assert not floating, f"these carry labels but track a moving ref: {floating}"


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


# ---------------------------------------------------------------------------
# A held-out miss is a count, not a to-do list
# ---------------------------------------------------------------------------


def _fake_corpus(tmp_path: Path, split: str) -> Path:
    """A one-repo corpus whose single label is unreachable, so it scores as a
    miss. `input()` mints an untrusted source, which keeps the scan challenged
    (an unchallenged target fails for a different reason and would mask this)."""
    repo = tmp_path / "repos" / "fake"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("def main():\n    q = input()\n    print(q)\n", encoding="utf-8")
    manifest = tmp_path / "repos.yaml"
    manifest.write_text(
        "threshold: 0.90\n"
        "repos:\n"
        "  - name: fake\n"
        "    url: https://example.invalid/fake\n"
        "    ref: deadbeef\n"
        "    kind: audited\n"
        f"    split: {split}\n"
        "    expect:\n"
        "      - {file: app.py, line: 3, rule: PI-SQL, verdict: flag,\n"
        "         mitigation: 'none', code: 'print(q)'}\n",
        encoding="utf-8",
    )
    return manifest


def test_a_held_out_miss_is_kept_out_of_the_default_detail(tmp_path: Path) -> None:
    """Rule 2, mechanically.

    `repo, file, line` for a held-out miss is a specification for the next
    engine change. A run that prints it by default publishes that list into
    every issue and commit message the output gets pasted into.
    """
    mod = _precision_module()
    m, _ = mod.score_repos(_fake_corpus(tmp_path, "held-out"), False)
    assert m.fn == 1, m.detail
    assert m.held_out_detail, "the miss went missing entirely"
    assert not [d for d in m.detail if d.startswith("FN")], (
        f"a held-out miss reached the default detail: {m.detail}"
    )
    assert "app.py" in m.held_out_detail[0], "the coordinates must still exist behind the flag"


def test_a_train_miss_stays_in_the_default_detail(tmp_path: Path) -> None:
    """Vacuity guard for the test above: if every miss were suppressed, that
    assertion would pass while the harness told nobody anything."""
    mod = _precision_module()
    m, _ = mod.score_repos(_fake_corpus(tmp_path, "train"), False)
    assert m.fn == 1
    assert not m.held_out_detail
    assert [d for d in m.detail if d.startswith("FN") and "app.py" in d], m.detail


def test_the_default_run_prints_a_count_not_coordinates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _precision_module()
    manifest = _fake_corpus(tmp_path, "held-out")
    monkeypatch.setattr(sys, "argv", ["precision.py", str(manifest), "--repos"])
    mod.main()
    out = capsys.readouterr().out
    assert "1 miss(es) across 1 repo(s)" in out
    assert "coordinates suppressed" in out
    assert "app.py" not in out, "the default run leaked a held-out coordinate"

    monkeypatch.setattr(
        sys, "argv", ["precision.py", str(manifest), "--repos", "--held-out-detail"]
    )
    mod.main()
    assert "app.py" in capsys.readouterr().out, "--held-out-detail must still show them"


# ---------------------------------------------------------------------------
# A labeller must never need to open a rule file
# ---------------------------------------------------------------------------
#
# Validating rule ids was not enough, and confirming that was the point of
# checking. PI-EXEC and PI-FRAMEWORK-EXEC share a sink category - both end in
# code execution - and differ only in the shape of the LLM call upstream. So
# "which id applies here?" could not be answered from the sink line, only from
# the rule definition, and the vocabulary leak reopened on every new label.
#
# Labels now match on what the sink DOES. These tests are what keep that true.


def test_every_label_declares_a_capability(corpus: dict) -> None:
    allowed = {"sql", "shell", "exec", "http", "handoff"}
    bad = [
        f"{r['name']}:{e['file']}:{e['line']} -> {e.get('capability')!r}"
        for r in corpus["repos"]
        for e in (r.get("expect") or [])
        if e.get("capability") not in allowed
    ]
    assert not bad, f"every label needs a `capability:` from {sorted(allowed)}: {bad}"


def test_the_exec_siblings_share_one_capability() -> None:
    """The load-bearing assertion.

    If these two ever map to different capabilities, assigning a label means
    deciding which one applies, which means reading their definitions, which is
    the leak. They are one capability precisely so the question never reaches a
    labeller.
    """
    mod = _precision_module()
    assert mod.RULE_CAPABILITY["PI-EXEC"] == mod.RULE_CAPABILITY["PI-FRAMEWORK-EXEC"] == "exec"


def test_every_shipped_rule_maps_to_a_capability() -> None:
    """A new rule with no mapping falls back to its own id, so its findings can
    never match a label written in capability terms - the labels would read as
    misses forever. Shipping a rule has to mean updating the table."""
    mod = _precision_module()
    unmapped = sorted(_shipped_rule_ids() - set(mod.RULE_CAPABILITY))
    assert not unmapped, f"these rules ship with no capability mapping: {unmapped}"


def test_a_capability_only_label_scores(tmp_path: Path) -> None:
    """The proof that `rule:` is no longer required of a labeller.

    The label below names no rule at all. It must still be scored - as a miss
    here, since nothing detects it - because a label that silently stopped
    counting would be the worst possible failure: recall would rise by losing
    its denominator.
    """
    mod = _precision_module()
    repo = tmp_path / "repos" / "fake"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("def main():\n    q = input()\n    print(q)\n", encoding="utf-8")
    manifest = tmp_path / "repos.yaml"
    manifest.write_text(
        "threshold: 0.90\n"
        "repos:\n"
        "  - name: fake\n"
        "    url: https://example.invalid/fake\n"
        "    ref: deadbeef\n"
        "    kind: audited\n"
        "    split: train\n"
        "    expect:\n"
        "      - {file: app.py, line: 3, capability: sql, verdict: flag,\n"
        "         mitigation: 'none', code: 'print(q)'}\n",
        encoding="utf-8",
    )
    m, _ = mod.score_repos(manifest, False)
    assert m.fn == 1, f"a capability-only label was not scored at all: {m.detail}"


def test_the_protocol_states_the_capability_rule() -> None:
    """Specific strings, deliberately: asserting the word "capability" appears
    passes on the phrase "dangerous capability", which the document used long
    before any of this - a vacuous test that would have told nobody anything."""
    text = PROTOCOL.read_text(encoding="utf-8")
    assert "capability: sql" in text, "the schema block must show the new field"
    assert "never a rule id" in text, "the rule has to be stated, not implied by an example"
    for token in ("`sql`", "`shell`", "`exec`", "`http`", "`handoff`"):
        assert token in text, f"the capability vocabulary is incomplete: {token} missing"


# ---------------------------------------------------------------------------
# Correlated paths must not inflate n
# ---------------------------------------------------------------------------


def _grouped_corpus(tmp_path: Path, groups: list[str]) -> Path:
    """One repo, three labels, with the given `group:` tags."""
    repo = tmp_path / "repos" / "fake"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(
        "def main():\n    q = input()\n    a = q\n    b = q\n    c = q\n", encoding="utf-8"
    )
    rows = "\n".join(
        f"      - {{file: app.py, line: {line}, capability: exec, verdict: flag,\n"
        f"         group: {g}, mitigation: 'none', code: '{var} = q'}}"
        for line, g, var in zip((3, 4, 5), groups, "abc", strict=True)
    )
    manifest = tmp_path / "repos.yaml"
    manifest.write_text(
        "threshold: 0.90\nrepos:\n  - name: fake\n"
        "    url: https://example.invalid/fake\n    ref: deadbeef\n"
        f"    kind: audited\n    split: held-out\n    expect:\n{rows}\n",
        encoding="utf-8",
    )
    return manifest


def test_paths_that_move_together_count_once(tmp_path: Path) -> None:
    """Three labels reached the same way are one observation, not three.

    The engine finds all three or none of them, so quoting n=3 claims more
    evidence than the set holds. Batch 2 is agent frameworks and code
    interpreters, where one planner can reach a capability several ways - the
    shape most likely to inflate a held-out count.
    """
    mod = _precision_module()
    m, _ = mod.score_repos(_grouped_corpus(tmp_path, ["a", "a", "a"]), False)
    assert m.fn == 3, "path-level counting must still see all three"
    rate, hits, total = m.group_recall_for("held-out")
    assert (hits, total) == (0, 1), f"three correlated paths collapsed to {total} group(s)"
    assert rate == 0.0


def test_independent_paths_still_count_separately(tmp_path: Path) -> None:
    """Vacuity guard: if grouping collapsed everything, the test above would
    pass while the harness reported effective n=1 for any corpus."""
    mod = _precision_module()
    m, _ = mod.score_repos(_grouped_corpus(tmp_path, ["a", "b", "c"]), False)
    _, _, total = m.group_recall_for("held-out")
    assert total == 3, f"three independent paths must stay three groups, got {total}"


def test_an_ungrouped_label_is_its_own_group(tmp_path: Path) -> None:
    """The safe default. Defaulting to a shared group would silently shrink the
    denominator, which raises recall - the direction that flatters."""
    mod = _precision_module()
    repo = tmp_path / "repos" / "fake"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("def main():\n    q = input()\n    a = q\n    b = q\n", "utf-8")
    manifest = tmp_path / "repos.yaml"
    manifest.write_text(
        "threshold: 0.90\nrepos:\n  - name: fake\n"
        "    url: https://example.invalid/fake\n    ref: deadbeef\n"
        "    kind: audited\n    split: held-out\n    expect:\n"
        "      - {file: app.py, line: 3, capability: exec, verdict: flag,\n"
        "         mitigation: 'none', code: 'a = q'}\n"
        "      - {file: app.py, line: 4, capability: exec, verdict: flag,\n"
        "         mitigation: 'none', code: 'b = q'}\n",
        encoding="utf-8",
    )
    m, _ = mod.score_repos(manifest, False)
    _, _, total = m.group_recall_for("held-out")
    assert total == 2, "labels with no `group:` must not share one"


def test_a_group_is_found_when_any_of_its_paths_is(Metrics) -> None:
    """A unit check, deliberately: the earlier draft of this test scanned the
    real 50-repo corpus, which took minutes in a suite that runs in eight
    seconds. A slow test gets skipped, and a skipped test guards nothing."""
    m = Metrics()
    m.groups_by_split = {"held-out": {("r", "a"): True, ("r", "b"): False, ("s", "a"): False}}
    rate, hits, total = m.group_recall_for("held-out")
    assert (hits, total) == (1, 3)
    assert abs(rate - 1 / 3) < 1e-9
    assert m.group_recall_for("train") is None, "an empty split reports None, never 1.000"


def test_a_group_tag_cannot_span_two_capabilities(tmp_path: Path) -> None:
    """Labellers tag across capabilities, so the split is enforced here.

    One batch put an exec sink and an http sink under one group letter; another
    put thirteen paths spanning four capabilities under one. Paths that exercise
    different capabilities cannot plausibly be found or missed together, so a
    shared tag across them would shrink the denominator for free. Enforced in
    the scorer rather than by editing the labeller's file - the labeller is the
    one who was blind, and their grouping within a capability is the judgement
    worth keeping.
    """
    mod = _precision_module()
    repo = tmp_path / "repos" / "fake"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("def main():\n    q = input()\n    a = q\n    b = q\n", "utf-8")
    manifest = tmp_path / "repos.yaml"
    manifest.write_text(
        "threshold: 0.90\nrepos:\n  - name: fake\n"
        "    url: https://example.invalid/fake\n    ref: deadbeef\n"
        "    kind: audited\n    split: held-out\n    expect:\n"
        "      - {file: app.py, line: 3, capability: exec, verdict: flag,\n"
        "         group: a, mitigation: 'none', code: 'a = q'}\n"
        "      - {file: app.py, line: 4, capability: http, verdict: flag,\n"
        "         group: a, mitigation: 'none', code: 'b = q'}\n",
        encoding="utf-8",
    )
    m, _ = mod.score_repos(manifest, False)
    _, _, total = m.group_recall_for("held-out")
    assert total == 2, f"one group tag spanning two capabilities must split, got {total}"


def test_the_capability_aggregation_is_the_pessimistic_bound(Metrics) -> None:
    """Three groups in one repo under one capability collapse to one
    observation. Reported alongside the labeller's grouping so the headline
    never rests on a judgement call about how correlated two paths really are -
    when the two disagree, the smaller number is the honest one."""
    m = Metrics()
    m.groups_by_split = {
        "held-out": {
            ("r", "exec", "a"): False,
            ("r", "exec", "b"): False,
            ("r", "exec", "c"): True,
            ("r", "sql", "d"): False,
        }
    }
    as_labelled = m.group_recall_for("held-out")
    per_capability = m.capability_recall_for("held-out")
    assert as_labelled[1:] == (1, 4)
    assert per_capability[1:] == (1, 2), "exec paths must collapse to one observation"
    assert per_capability[0] > as_labelled[0], (
        "collapsing a denominator raises the rate - which is exactly why both "
        "are printed and the smaller n is the one quoted"
    )


def test_capability_aggregation_is_empty_for_an_empty_split(Metrics) -> None:
    m = Metrics()
    assert m.capability_recall_for("held-out") is None


def test_the_leak_tripwire_still_fires_on_a_real_mention() -> None:
    """Vacuity guard for the boundary fix above.

    Two false alarms were tightened away in a row; a third tightening could
    silently disarm the check entirely. `vanna` is genuinely diagnosed in
    proof-scans.md, so the matcher must still see it.
    """
    diagnosed = PROOF.read_text(encoding="utf-8")
    assert re.search(r"(?<![A-Za-z0-9])vanna(?![A-Za-z0-9])", diagnosed), (
        "the tripwire no longer matches a repo that IS diagnosed - it has been "
        "tightened into uselessness"
    )
    assert not re.search(r"(?<![A-Za-z0-9])agno(?![A-Za-z0-9])", diagnosed), (
        "the boundary fix did not take: `agno` still matches inside `diagnosed`"
    )


def test_the_protocol_records_that_ground_truth_is_incomplete() -> None:
    """The caveat has to survive editing, because it is the one that protects
    every recall number in the project.

    A reviewer who finds an unlabelled sibling of a labelled path - and one
    exists, that is how this was discovered - will otherwise conclude the
    benchmark is sloppy rather than incomplete in a direction we declared. The
    direction is the load-bearing part: the numerator is what the engine found
    and the denominator is smaller than the truth, so a published recall figure
    is an overestimate.
    """
    text = PROTOCOL.read_text(encoding="utf-8")
    assert "known-incomplete" in text, "the incompleteness caveat is gone"
    assert "OVERESTIMATE" in text or "overestimate" in text, (
        "the caveat must state the DIRECTION of the bias, not merely that one exists"
    )
    assert "singlestore" in text, "the caveat must name the path that revealed it"
