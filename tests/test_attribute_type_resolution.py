"""Attribute-type resolution across object boundaries.

Specified in `docs/roadmap.md` from four train misses, and built as the general
capability rather than as four fixes: an attribute or local holds an object, the
object has a type, and a call on it resolves through that type's hierarchy. The
traversal names no attribute, no library and no repo - a reviewer reading it
cannot tell which four repos motivated it. Provider names live in rule data,
where `chat.completions.create` has always lived.

Three sources of an attribute's type, all general:

  self.x = T(...)              constructed, read from any method
  x: T = field(...)            declared in the class body
  def __init__(self, x: T)     declared on a parameter that is stored on self

And one consequence that only shows up once the boundary is crossed: a framework
entry point is routinely a template method on an abstract base, so `self.hook()`
inside it has as many implementations as there are subclasses. Unresolvable in
general - but unambiguous when the attribute that got us in declared what it
holds, which is what `recv_type` threads through.

The silence tests carry the weight. Crossing an object boundary propagates taint
further before it surfaces than seeding it at a function boundary does, so a
wrong type mapping produces findings a long way from the mistake.
"""

from __future__ import annotations

from pathlib import Path

from palisade_sec.scanner import run_scan


def _write(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


# --- constructed attribute: the object is built in __init__ -----------------


def test_a_call_on_a_constructed_attribute_is_resolved(tmp_path: Path) -> None:
    """`self.gen = dspy.ChainOfThought(...)` in one method, `self.gen(...)` in
    another. The call site names only the attribute, so without the type the
    LLM hop is invisible and the path cannot be reported at all."""
    res = run_scan(
        _write(
            tmp_path,
            {
                "pot.py": "import dspy\n\n\n"
                "class ProgramOfThought(dspy.Module):\n"
                "    def __init__(self, signature):\n"
                "        self.code_generate = dspy.ChainOfThought(signature)\n\n"
                "    def _execute_code(self, code, interpreter):\n"
                "        return interpreter.execute(code)\n\n"
                "    def forward(self, question):\n"
                "        data = self.code_generate(question=question)\n"
                "        return self._execute_code(data.generated_code, None)\n"
            },
        ),
        assume_params_untrusted=True,
    )
    assert res.findings, "a call on a constructed attribute was not recognised"
    f = res.findings[0]
    assert "interpreter.execute" in f.sink.snippet
    assert f.llm.detail == "dspy.ChainOfThought", (
        f"the trace must name the resolved type, got {f.llm.detail!r}"
    )


# --- declared attribute, across two object boundaries and a base class ------

_DRIVER = """import sqlalchemy


class SqlDriver:
    def execute_query(self, query: str):
        with self.engine.connect() as con:
            results = con.execute(sqlalchemy.text(query))
            return results
"""

_LOADER = """from attrs import define, field

from driver import SqlDriver


class BaseLoader:
    def load(self, source: str):
        return self.fetch(source)


@define
class SqlLoader(BaseLoader):
    sql_driver: SqlDriver = field(kw_only=True)

    def fetch(self, source: str):
        return self.sql_driver.execute_query(source)


class CsvLoader(BaseLoader):
    def fetch(self, source: str):
        return source.splitlines()


class WebLoader(BaseLoader):
    def fetch(self, source: str):
        return source.strip()
"""

_TOOL = """from attrs import define, field

from griptape.utils.decorators import activity
from loader import SqlLoader


@define
class SqlTool:
    sql_loader: SqlLoader = field(kw_only=True)

    @activity(config={"description": "run a query"})
    def execute_query(self, params: dict):
        query = params["values"]["sql_query"]
        return self.sql_loader.load(query)
"""


def test_two_object_boundaries_and_a_template_method(tmp_path: Path) -> None:
    """The full shape, and the reason `recv_type` exists.

    `load` is defined on the base class and calls `self.fetch(...)`, which the
    base does not implement. THREE subclasses implement it, which is what makes
    the receiver's type necessary rather than merely convenient: with one
    implementation, ordinary unique-descendant resolution suffices and this test
    proves nothing. Mutation testing caught exactly that - the first version of
    this fixture passed with receiver-context resolution disabled.
    """
    res = run_scan(_write(tmp_path, {"driver.py": _DRIVER, "loader.py": _LOADER, "tool.py": _TOOL}))
    assert res.findings, "the two-boundary chain did not resolve"
    f = res.findings[0]
    assert f.sink.file == "driver.py"
    assert "con.execute" in f.sink.snippet
    assert f.source.detail.startswith("tool-arg:")


def test_the_chain_needs_the_declared_type(tmp_path: Path) -> None:
    """Vacuity guard for the test above. Strip the annotation and the same code
    must go silent - otherwise the finding came from somewhere else and the
    test proves nothing about type resolution."""
    loader = _LOADER.replace("    sql_driver: SqlDriver = field(kw_only=True)", "    pass")
    res = run_scan(_write(tmp_path, {"driver.py": _DRIVER, "loader.py": loader, "tool.py": _TOOL}))
    assert res.findings == [], (
        "the chain resolved without a declared type, so the test above is not "
        "measuring attribute-type resolution"
    )


def test_an_init_parameter_annotation_is_a_type_source(tmp_path: Path) -> None:
    res = run_scan(
        _write(
            tmp_path,
            {
                "driver.py": _DRIVER,
                "svc.py": "from driver import SqlDriver\n\n\n"
                "class Service:\n"
                "    def __init__(self, driver: SqlDriver):\n"
                "        self.driver = driver\n\n"
                "    def handle(self, request):\n"
                "        q = request.json['q']\n"
                "        answer = llm.invoke(q)\n"
                "        return self.driver.execute_query(answer)\n",
            },
        )
    )
    assert res.findings, "an annotated __init__ parameter stored on self is a type source"
    assert res.findings[0].sink.file == "driver.py"


def test_a_local_holding_a_constructed_object_resolves(tmp_path: Path) -> None:
    res = run_scan(
        _write(
            tmp_path,
            {
                "driver.py": _DRIVER,
                "app.py": "from driver import SqlDriver\n\n\n"
                "def handle(request):\n"
                "    q = request.json['q']\n"
                "    answer = llm.invoke(q)\n"
                "    driver = SqlDriver()\n"
                "    return driver.execute_query(answer)\n",
            },
        )
    )
    assert res.findings, "a local assigned a constructor call was not resolved"


# --- silence: where a resolved type must NOT create a path ------------------


def test_silent_when_the_attribute_never_held_model_output(tmp_path: Path) -> None:
    """The type resolves, the sink is real, and there is no model on the path.
    Untrusted input reaching a sink without an LLM is out of contract."""
    res = run_scan(
        _write(
            tmp_path,
            {
                "driver.py": _DRIVER,
                "app.py": "from driver import SqlDriver\n\n\n"
                "class Service:\n"
                "    def __init__(self, driver: SqlDriver):\n"
                "        self.driver = driver\n\n"
                "    def handle(self, request):\n"
                "        return self.driver.execute_query(request.json['q'])\n",
            },
        )
    )
    assert res.findings == [], "a path with no LLM hop must stay silent"


def test_silent_when_the_attribute_holds_a_non_llm_object(tmp_path: Path) -> None:
    """A constructed attribute is only an LLM call when its type says so.
    Otherwise every object built in __init__ and called later becomes a model."""
    res = run_scan(
        _write(
            tmp_path,
            {
                "app.py": "import templating\n\n\n"
                "class Renderer:\n"
                "    def __init__(self):\n"
                "        self.render = templating.Engine()\n\n"
                "    def handle(self, request):\n"
                "        out = self.render(request.json['q'])\n"
                "        exec(out)\n"
            },
        )
    )
    assert res.findings == [], "a non-LLM constructed object must not satisfy the LLM hop"


def test_an_imported_type_is_not_ambiguous(tmp_path: Path) -> None:
    """Worth pinning, because it was the first thing I got wrong about this.

    Two classes share a name, but `from a import Store` says which one the
    annotation means, so resolving it is correct rather than a guess. The import
    is the disambiguator, and the alias table already carries it.
    """
    res = run_scan(
        _write(
            tmp_path,
            {
                "a.py": "class Store:\n"
                "    def run(self, q):\n"
                "        self.conn.cursor().execute(q)\n",
                "b.py": "class Store:\n    def run(self, q):\n        return len(q)\n",
                "app.py": "from a import Store\n\n\n"
                "class Service:\n"
                "    def __init__(self, store: Store):\n"
                "        self.store = store\n\n"
                "    def handle(self, request):\n"
                "        answer = llm.invoke(request.json['q'])\n"
                "        return self.store.run(answer)\n",
            },
        )
    )
    assert [f.sink.file for f in res.findings] == ["a.py"], (
        "the import names which Store is meant; resolution must follow it"
    )


def test_ambiguous_types_are_not_guessed(tmp_path: Path) -> None:
    """With nothing to disambiguate - an unimported name, two classes that both
    implement the method - the engine must not pick one. Guessing is how a
    taint path gets invented, and it is the same restraint that leaves
    many-provider dispatch unresolved.
    """
    res = run_scan(
        _write(
            tmp_path,
            {
                "a.py": "class Store:\n"
                "    def run(self, q):\n"
                "        self.conn.cursor().execute(q)\n",
                "b.py": "class Store:\n"
                "    def run(self, q):\n"
                "        self.conn.cursor().execute(q)\n",
                "app.py": "class Service:\n"
                "    def __init__(self, store: Store):\n"
                "        self.store = store\n\n"
                "    def handle(self, request):\n"
                "        answer = llm.invoke(request.json['q'])\n"
                "        return self.store.run(answer)\n",
            },
        )
    )
    assert res.findings == [], (
        "an unresolvable type name must not resolve to one of its candidates: "
        f"{[(f.sink.file, f.sink.snippet) for f in res.findings]}"
    )
