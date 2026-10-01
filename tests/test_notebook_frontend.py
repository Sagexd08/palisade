"""Jupyter notebook frontend: reassembles .ipynb code cells into Python
source and delegates to PythonFrontend - same engine, zero engine changes,
mirroring test_js_frontend.py's role for the JS/TS frontend."""

from __future__ import annotations

import json
import textwrap

import pytest

from palisade_sec.frontends.notebook import NotebookFrontend, reassemble
from palisade_sec.report import to_sarif
from palisade_sec.scanner import run_scan


def _notebook(*cells: tuple[str, str], language: str = "python") -> str:
    """Build minimal nbformat JSON from (cell_type, source) pairs."""
    doc = {
        "cells": [
            {
                "cell_type": kind,
                "execution_count": None,
                "metadata": {},
                "source": textwrap.dedent(src).strip("\n").splitlines(keepends=True),
                "outputs": [] if kind == "code" else [],
            }
            for kind, src in cells
        ],
        "metadata": {"language_info": {"name": language}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    return json.dumps(doc)


def _scan(tmp_path, name: str, notebook_json: str):
    (tmp_path / name).write_text(notebook_json, encoding="utf-8")
    return run_scan(tmp_path)


# ---------------------------------------------------------------------------
# end to end: must flag / must stay silent, through the real scan pipeline
# ---------------------------------------------------------------------------


def test_injection_split_across_cells_is_flagged(tmp_path):
    # The realistic notebook shape: setup in one cell, the vulnerable call in
    # another - reassembly (not per-cell parsing) is what makes this visible.
    nb = _notebook(
        (
            "code",
            """
            %matplotlib inline
            import openai
            from flask import request
            client = openai.OpenAI()
            """,
        ),
        (
            "markdown",
            "# Ask the model to write some code",
        ),
        (
            "code",
            """
            def ask():
                question = request.json["question"]
                resp = client.chat.completions.create(
                    model="gpt-4", messages=[{"role": "user", "content": question}]
                )
                code = resp.choices[0].message.content
                exec(code)
            """,
        ),
    )
    res = _scan(tmp_path, "vuln.ipynb", nb)
    assert res.skipped == [], res.skipped
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    f = res.findings[0]
    assert f.severity == "high"
    assert f.source.file == "vuln.ipynb"
    assert f.sink.snippet == "exec(code)"


def test_safe_notebook_is_silent(tmp_path):
    nb = _notebook(("code", "x = 1 + 1\nprint(x)\n"))
    res = _scan(tmp_path, "safe.ipynb", nb)
    assert res.skipped == []
    assert res.findings == []


def test_markdown_only_notebook_is_silent(tmp_path):
    nb = _notebook(("markdown", "# just notes, no code"))
    res = _scan(tmp_path, "notes.ipynb", nb)
    assert res.skipped == []
    assert res.findings == []


# ---------------------------------------------------------------------------
# resilience: malformed / non-Python input never crashes the scan
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content, reason_contains",
    [
        pytest.param("not json at all {{{", "not a readable Jupyter notebook", id="invalid-json"),
        pytest.param("[]", "not a readable Jupyter notebook", id="json-not-an-object"),
        pytest.param('{"nbformat": 4}', "not a readable Jupyter notebook", id="missing-cells"),
        pytest.param(
            json.dumps({"cells": [{"cell_type": "code", "source": "x = 1 +"}]}),
            None,  # a real ast.parse SyntaxError, message not pinned here
            id="cell-body-is-invalid-python",
        ),
    ],
)
def test_malformed_notebook_is_skipped_not_crashed(tmp_path, content, reason_contains):
    res = _scan(tmp_path, "bad.ipynb", content)
    assert res.findings == []
    assert len(res.skipped) == 1
    if reason_contains:
        assert reason_contains in res.skipped[0]


def test_non_python_kernel_is_skipped(tmp_path):
    nb = _notebook(("code", "x <- 1 + 1"), language="R")
    res = _scan(tmp_path, "r_notebook.ipynb", nb)
    assert res.findings == []
    assert "not python" in res.skipped[0]


def test_magic_and_shell_lines_do_not_break_parsing(tmp_path):
    nb = _notebook(
        (
            "code",
            """
            !pip install openai
            %%time
            %env FOO=bar
            import openai
            """,
        )
    )
    res = _scan(tmp_path, "magics.ipynb", nb)
    assert res.skipped == [], res.skipped


# ---------------------------------------------------------------------------
# reassemble(): the pure text-transformation unit, independent of ast.parse
# ---------------------------------------------------------------------------


def test_reassemble_returns_none_for_non_notebook_text():
    assert reassemble("print('hello')") is None
    assert reassemble("{}") is None


def test_reassemble_inserts_a_marker_line_per_cell():
    nb = _notebook(("code", "a = 1"), ("code", "b = 2"))
    combined = reassemble(nb)
    assert combined is not None
    assert combined.count("# In[") == 2


def test_notebook_frontend_extensions_and_name():
    fe = NotebookFrontend()
    assert fe.extensions == (".ipynb",)
    assert fe.name == "jupyter"


# ---------------------------------------------------------------------------
# inline suppressions: a `palisade: ignore` written inside a cell must work
#
# The raw `.ipynb` is JSON, so reading suppressions off the file text would
# make every in-cell comment silently inert - the finding keeps firing, and
# the user who marked it reviewed gets no explanation. Invariant 10:
# suppressions stay loud. The seam is `Frontend.suppression_source`.
# ---------------------------------------------------------------------------

_SETUP_CELL = """
import openai
from flask import request
client = openai.OpenAI()
"""

_SINK_CELL = """
def ask():
    question = request.json["question"]
    resp = client.chat.completions.create(
        model="gpt-4", messages=[{"role": "user", "content": question}]
    )
    code = resp.choices[0].message.content
    exec(code)
"""


def _two_cell_notebook(sink_cell: str = _SINK_CELL) -> str:
    return _notebook(("code", _SETUP_CELL), ("code", sink_cell))


def test_notebook_without_suppression_still_fires(tmp_path):
    # The control for the two tests below: same notebook, no comment.
    res = _scan(tmp_path, "nb.ipynb", _two_cell_notebook())
    assert res.skipped == [], res.skipped
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    assert res.suppressed == []


def test_in_cell_suppression_silences_the_finding(tmp_path):
    sink = _SINK_CELL.replace(
        "exec(code)", "exec(code)  # palisade: ignore[PI-EXEC] - reviewed, sandboxed"
    )
    res = _scan(tmp_path, "nb.ipynb", _two_cell_notebook(sink))
    assert res.skipped == [], res.skipped
    assert res.findings == []
    # Loud, not silent: counted, attributable, and carrying the reason.
    assert len(res.suppressed) == 1
    entry = res.suppressed[0]
    assert entry["rule"] == "PI-EXEC"
    assert entry["file"] == "nb.ipynb"
    assert entry["reason"] == "reviewed, sandboxed"
    # The line recorded is a reassembled-source line, the same convention
    # every other notebook line number follows.
    assert entry["suppressed_at"] == entry["line"]
    assert any("silenced by inline" in n for n in res.notes)


def test_suppression_on_the_line_above_works_in_a_cell(tmp_path):
    sink = _SINK_CELL.replace(
        "    exec(code)",
        "    # palisade: ignore[PI-EXEC] - reviewed\n    exec(code)",
    )
    res = _scan(tmp_path, "nb.ipynb", _two_cell_notebook(sink))
    assert res.skipped == [], res.skipped
    assert res.findings == []
    assert len(res.suppressed) == 1


def test_stale_in_cell_suppression_is_reported(tmp_path):
    # A comment in a notebook that silences nothing must be reported stale,
    # exactly as in a .py file - otherwise it lingers and masks a future
    # finding. `x = 1` is not a sink, so this one matches nothing.
    nb = _notebook(("code", "x = 1  # palisade: ignore[PI-EXEC] - nothing here\n"))
    res = _scan(tmp_path, "stale.ipynb", nb)
    assert res.skipped == [], res.skipped
    assert res.findings == []
    stale = [n for n in res.notes if "stale `palisade: ignore`" in n]
    assert len(stale) == 1
    # Reported against a reassembled-source line: `# In[0]:` is line 1, so
    # the first cell's first line - and the comment - is line 2.
    assert "stale.ipynb:2" in stale[0]


def test_suppression_comment_in_a_markdown_cell_is_not_read_as_code(tmp_path):
    # Markdown cells contribute their `# In[N]:` marker line only, so prose
    # that happens to contain the magic string cannot silence anything - it
    # is reported stale rather than quietly disabling a rule.
    nb = _notebook(
        ("markdown", "Do not write `# palisade: ignore[PI-EXEC]` here, it does nothing"),
        ("code", _SETUP_CELL),
        ("code", _SINK_CELL),
    )
    res = _scan(tmp_path, "md.ipynb", nb)
    assert res.skipped == [], res.skipped
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    assert res.suppressed == []


def test_suppression_source_is_the_reassembled_text_not_the_json():
    nb = _two_cell_notebook()
    assert NotebookFrontend().suppression_source(nb) == reassemble(nb)


def test_suppression_source_of_an_unreadable_notebook_is_empty():
    # `lower_file` reports a ParseFailure for these, so the scanner never
    # reaches the suppression seam - but it must not raise if it does.
    assert NotebookFrontend().suppression_source("not json at all {{{") == ""


# ---------------------------------------------------------------------------
# SARIF: a notebook line is NOT a line of the file on disk
# ---------------------------------------------------------------------------


def test_sarif_anchors_a_notebook_finding_at_the_file(tmp_path):
    res = _scan(tmp_path, "vuln.ipynb", _two_cell_notebook())
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    finding = res.findings[0]
    # The finding itself keeps the reassembled line (the --json contract).
    assert finding.line > 1
    doc = json.loads(to_sarif(res.findings))
    result = doc["runs"][0]["results"][0]

    region = result["locations"][0]["physicalLocation"]["region"]
    # Anchored at the file, not at a line of JSON that means nothing - and
    # the region is still PRESENT, because GitHub code scanning requires
    # `region.startLine` and rejects a whole run without it.
    assert region["startLine"] == 1
    assert region["snippet"]["text"] == "exec(code)"
    for related in result["relatedLocations"]:
        assert related["physicalLocation"]["region"]["startLine"] == 1

    # The real line is not lost: carried in prose and machine-readably.
    assert f"line {finding.line} of the reassembled notebook source" in result["message"]["text"]
    assert result["properties"]["palisade/notebookSinkLine"] == finding.line


def test_sarif_still_uses_real_lines_for_python_files(tmp_path):
    # The notebook carve-out must not leak into ordinary files.
    (tmp_path / "app.py").write_text(
        textwrap.dedent(_SETUP_CELL) + textwrap.dedent(_SINK_CELL), encoding="utf-8"
    )
    res = run_scan(tmp_path)
    assert [f.rule_id for f in res.findings] == ["PI-EXEC"]
    finding = res.findings[0]
    result = json.loads(to_sarif(res.findings))["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == finding.line
    assert "properties" not in result
    assert "reassembled notebook" not in result["message"]["text"]
