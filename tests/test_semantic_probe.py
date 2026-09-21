"""PROBE is deterministic and offline: given source, it must find the right
tools and the exact capabilities their bodies exercise - no judgments, no
network. These tests never touch TypeSafe."""

from __future__ import annotations

from palisade_sec.frontends.ast_python import ParseFailure, PythonFrontend
from palisade_sec.semantic.probe import harvest_tools

SOURCE = """
import os
import subprocess
import stripe
from langchain.tools import tool
from agents import function_tool


@tool
def run_command(cmd: str) -> str:
    "Run a shell command and return its output."
    subprocess.run(cmd, shell=True)
    return os.system(cmd)


@function_tool
def charge_card(customer: str, amount: int):
    "Charge a customer's card."
    return stripe.PaymentIntent.create(customer=customer, amount=amount)


@tool
def format_name(first: str, last: str) -> str:
    "Pure computation - no capabilities."
    return f"{first} {last}".title()


def internal_helper(cmd: str):
    # Not a tool (no decorator) - must NOT be harvested even though it is dangerous.
    os.system(cmd)
"""


def _lower(src: str):
    mod = PythonFrontend().lower_file("t.py", "t.py", src)
    assert not isinstance(mod, ParseFailure)
    return [mod]


def test_harvests_only_decorated_tools():
    tools = harvest_tools(_lower(SOURCE))
    names = {t.name for t in tools}
    assert names == {"run_command", "charge_card", "format_name"}
    assert "internal_helper" not in names  # dangerous, but not a tool


def test_shell_tool_capabilities_and_evidence():
    tools = {t.name: t for t in harvest_tools(_lower(SOURCE))}
    shell = tools["run_command"]
    assert shell.capabilities == ["shell"]
    # both subprocess.run and os.system are recorded as grounded evidence
    paths = {h.func_path for h in shell.capability_hits}
    assert paths == {"subprocess.run", "os.system"}
    assert all(h.snippet for h in shell.capability_hits)
    assert shell.docstring.startswith("Run a shell command")


def test_payments_capability():
    tools = {t.name: t for t in harvest_tools(_lower(SOURCE))}
    assert "payments" in tools["charge_card"].capabilities


def test_pure_tool_has_no_capabilities():
    tools = {t.name: t for t in harvest_tools(_lower(SOURCE))}
    assert tools["format_name"].capabilities == []
    assert tools["format_name"].capability_hits == []


def test_agent_dot_tool_decorator_matches():
    src = (
        "from pydantic_ai import Agent\n"
        "agent = Agent()\n"
        "import shutil\n"
        "@agent.tool\n"
        "def wipe(path: str):\n"
        "    shutil.rmtree(path)\n"
    )
    tools = harvest_tools(_lower(src))
    assert len(tools) == 1
    assert tools[0].name == "wipe"
    assert tools[0].capabilities == ["file_write"]


# -- guard tracking (structural fact for the excessive-agency `gated` signal) -


def test_unconditional_call_is_not_guarded():
    tools = {t.name: t for t in harvest_tools(_lower(SOURCE))}
    shell = tools["run_command"]
    assert all(not h.guarded for h in shell.capability_hits)
    assert all(h.guard_condition == "" for h in shell.capability_hits)


def test_call_inside_if_is_guarded_with_condition_text():
    src = (
        "import stripe\n"
        "from agents import function_tool\n"
        "@function_tool\n"
        "def refund(order_id: str):\n"
        '    "Refund an order, but only after explicit human approval."\n'
        "    if require_human_approval(order_id):\n"
        "        stripe.PaymentIntent.create(order_id)\n"
    )
    tools = harvest_tools(_lower(src))
    assert len(tools) == 1
    hits = tools[0].capability_hits
    assert len(hits) == 1
    assert hits[0].guarded is True
    assert "require_human_approval" in hits[0].guard_condition


def test_call_in_else_branch_is_also_guarded():
    src = (
        "import stripe\n"
        "from agents import function_tool\n"
        "@function_tool\n"
        "def refund(order_id: str, dry_run: bool):\n"
        "    if dry_run:\n"
        "        pass\n"
        "    else:\n"
        "        stripe.PaymentIntent.create(order_id)\n"
    )
    tools = harvest_tools(_lower(src))
    hits = tools[0].capability_hits
    assert len(hits) == 1
    assert hits[0].guarded is True
    assert "dry_run" in hits[0].guard_condition


def test_call_after_unrelated_guard_is_still_unconditional():
    # a guard that exists in the function but does not enclose the dangerous
    # call must not make the call look gated.
    src = (
        "import os\n"
        "from langchain.tools import tool\n"
        "@tool\n"
        "def maybe_run(cmd: str, verbose: bool):\n"
        "    if verbose:\n"
        "        print('running')\n"
        "    os.system(cmd)\n"
    )
    tools = harvest_tools(_lower(src))
    hits = tools[0].capability_hits
    assert len(hits) == 1
    assert hits[0].guarded is False


def test_excessive_agency_state_carries_guard_facts():
    from palisade_sec.semantic.judge import excessive_agency_state

    src = (
        "import stripe\n"
        "from agents import function_tool\n"
        "@function_tool\n"
        "def refund(order_id: str):\n"
        "    if require_human_approval(order_id):\n"
        "        stripe.PaymentIntent.create(order_id)\n"
    )
    tools = harvest_tools(_lower(src))
    state = excessive_agency_state(tools[0])
    assert state["guard_facts"] == [
        {
            "call": "stripe.PaymentIntent.create",
            "guarded_by_if": True,
            "if_condition": "if require_human_approval(order_id):",
        }
    ]
