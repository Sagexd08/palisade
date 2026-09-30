"""The two train-documented recall gaps, closed and pinned.

Both fixes are specified in `docs/roadmap.md` from train misses only, by
coordinate and verbatim sink, and the shapes below are reductions of those
misses - not of any held-out path. The held-out half exists to measure whether
these generalize, so it contributed nothing to the design and nothing here.

Gap 1 - tool-call arguments as model output. An agent tool's arguments are
written by the model, so a tool body reaching a dangerous sink is already a
complete path: the LLM hop happened at the function boundary. The model call
itself lives in the framework's dispatch loop, often in another package, so
requiring a visible source -> LLM chain made the whole class unreachable.

Gap 2 - LLM call shapes that were not recognised as LLM calls.

The silence tests matter more than the flag tests. Gap 1 seeds LLM taint at a
function boundary, which is the most dangerous thing in this engine: get the
marker wrong and every method named `run` starts a finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from palisade_sec.scanner import run_scan

# --- gap 1: the three train shapes ------------------------------------------

CREWAI_SHAPE = """\
from crewai.tools.base_tool import BaseTool


class SnowflakeSearchTool(BaseTool):
    name = "snowflake"

    def _run(self, query: str, timeout: int = 30) -> str:
        cursor = self.conn.cursor()
        cursor.execute(query, timeout=timeout)
        return str(cursor.fetchall())
"""

AUTOGEN_SHAPE = """\
from autogen_core.tools import BaseTool


class PythonCodeExecutionTool(BaseTool):
    async def run(self, args, cancellation_token):
        return await self._executor.execute_code_blocks(args.code, cancellation_token)
"""

GRIPTAPE_SHAPE = """\
from griptape.utils.decorators import activity


class SqlTool:
    @activity(config={"description": "Run a query"})
    def run_query(self, params: dict) -> str:
        query = params["values"]["sql_query"]
        return self.conn.execute(query)
"""


def _scan(tmp_path: Path, name: str, body: str, **kw):
    (tmp_path / name).write_text(body, encoding="utf-8")
    return run_scan(tmp_path, **kw)


@pytest.mark.parametrize(
    ("name", "body", "sink"),
    [
        ("tool_sql.py", CREWAI_SHAPE, "cursor.execute"),
        ("tool_exec.py", AUTOGEN_SHAPE, "execute_code_blocks"),
    ],
)
def test_gap1_flags_a_tool_body_reaching_a_sink(tmp_path: Path, name, body, sink) -> None:
    res = _scan(tmp_path, name, body)
    assert res.findings, f"gap 1 did not fire on {name}"
    f = res.findings[0]
    assert sink in f.sink.snippet
    assert f.source.detail.startswith("tool-arg:"), (
        f"the trace must name the tool argument as the origin, got {f.source.detail}"
    )


def test_gap1_needs_no_library_mode(tmp_path: Path) -> None:
    """The point of the fix. These paths were unreachable without
    --assume-params-untrusted, and a framework's own repo is scanned in app
    mode by default, so the class of finding never appeared."""
    res = _scan(tmp_path, "tool_sql.py", CREWAI_SHAPE)
    assert res.findings, "a tool body must be reachable in app mode"


def test_gap1_decorator_form(tmp_path: Path) -> None:
    res = _scan(tmp_path, "griptape_tool.py", GRIPTAPE_SHAPE)
    assert res.findings, "the @activity decorator form did not fire"
    assert res.findings[0].source.detail.startswith("tool-arg:")


# --- gap 1: where it must stay silent ---------------------------------------


def test_gap1_is_silent_on_a_tool_with_no_sink(tmp_path: Path) -> None:
    res = _scan(
        tmp_path,
        "harmless.py",
        "from crewai.tools.base_tool import BaseTool\n\n\n"
        "class EchoTool(BaseTool):\n"
        "    def _run(self, text: str) -> str:\n"
        "        return text.upper()\n",
    )
    assert res.findings == []


def test_gap1_is_silent_on_a_method_named_run_that_is_not_a_tool(tmp_path: Path) -> None:
    """The dangerous false positive this fix could cause. `run` is one of the
    most common method names in Python; only a tool base class makes its
    arguments model output."""
    res = _scan(
        tmp_path,
        "migration.py",
        "class Migration:\n"
        "    def run(self, statement: str) -> None:\n"
        "        self.conn.cursor().execute(statement)\n",
    )
    assert res.findings == [], (
        "a plain class with a run() method must not be treated as an agent tool"
    )


def test_gap1_is_silent_on_an_unrelated_basetool(tmp_path: Path) -> None:
    """`BaseTool` is matched on the class hierarchy, not the word. A class
    deriving from something else entirely keeps its params untainted."""
    res = _scan(
        tmp_path,
        "other.py",
        "class BaseWidget:\n    pass\n\n\n"
        "class Widget(BaseWidget):\n"
        "    def run(self, statement: str) -> None:\n"
        "        self.conn.cursor().execute(statement)\n",
    )
    assert res.findings == []


# --- gap 2: LLM call shapes -------------------------------------------------


def test_gap2_recognises_model_client_create(tmp_path: Path) -> None:
    res = _scan(
        tmp_path,
        "agent.py",
        "def handle(request):\n"
        "    task = request.json['task']\n"
        "    response = model_client.create([task])\n"
        "    exec(response.content)\n",
    )
    assert res.findings, "model_client.create is not recognised as an LLM call"
    assert "model_client.create" in res.findings[0].llm.detail


def test_gap2_recognises_prompt_driver_run(tmp_path: Path) -> None:
    res = _scan(
        tmp_path,
        "task.py",
        "class PromptTask:\n"
        "    def run(self, question):\n"
        "        output = self.prompt_driver.run(question)\n"
        "        exec(output.value)\n",
        assume_params_untrusted=True,
    )
    assert res.findings, "prompt_driver.run is not recognised as an LLM call"
    assert "prompt_driver.run" in res.findings[0].llm.detail


def test_gap2_does_not_treat_every_create_as_an_llm_call(tmp_path: Path) -> None:
    """Signatures are named exactly for this reason. `*.create` would make any
    ORM or factory call an LLM hop, and the engine's whole contract is that a
    finding needs a real model in the middle."""
    res = _scan(
        tmp_path,
        "orm.py",
        "def handle(request):\n"
        "    name = request.json['name']\n"
        "    row = Session.create(name)\n"
        "    exec(row.script)\n",
    )
    assert res.findings == [], "a non-LLM .create() must not satisfy the LLM hop"


def test_gap1_only_seeds_the_tool_entry_points(tmp_path: Path) -> None:
    """A mutation-driven test: dropping the method-name check broke nothing.

    Only the framework's declared entry point receives model-written arguments.
    A helper on the same class is called by whatever calls it - if that is the
    tool body, taint propagates through the call and the finding still appears
    (the test above covers that). Seeding every method instead would make a
    cache-key or a formatter into a tool argument and manufacture findings.
    """
    res = _scan(
        tmp_path,
        "tool_helper.py",
        "from crewai.tools.base_tool import BaseTool\n\n\n"
        "class ReportTool(BaseTool):\n"
        "    def _run(self, query: str) -> str:\n"
        "        return str(query)\n\n"
        "    def refresh_schema(self, table: str) -> None:\n"
        "        self.conn.cursor().execute(table)\n",
    )
    assert res.findings == [], (
        "only run/_run carry model-written arguments; a helper method on a tool "
        f"class must not be seeded: {[(f.sink.snippet, f.source.detail) for f in res.findings]}"
    )
