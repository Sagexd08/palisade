"""Installable guardrails for LLM-output-to-dangerous-sink paths.

Deterministic and fully offline, in keeping with the tool's safety contract -
no LLM, no network. Same validation semantics as the templates `fix` used to
only print as markdown; these are importable so a finding's remediation is a
real dependency instead of a copy-paste transcription.

    from palisade_sec.guardrails import validate_generated_code, run_model_command

Each guard is a strict allowlist - never a denylist, never a confirmation
prompt alone - because those have been bypassed in the real CVEs this tool
tracks (see rules/pi-*.yaml `references`).
"""

from __future__ import annotations

from palisade_sec.guardrails.exec_ import UnsafeCodeError, validate_generated_code
from palisade_sec.guardrails.http import UnsafeURLError, validate_outbound_url
from palisade_sec.guardrails.shell import UnsafeCommandError, run_model_command
from palisade_sec.guardrails.sql import UnsafeSQLError, validate_generated_sql

__all__ = [
    "UnsafeCodeError",
    "UnsafeCommandError",
    "UnsafeSQLError",
    "UnsafeURLError",
    "validate_generated_code",
    "run_model_command",
    "validate_generated_sql",
    "validate_outbound_url",
]

# family -> the guard's importable name, so fix.py can point at it without
# inlining the whole module path by hand.
GUARDRAIL_BY_FAMILY: dict[str, str] = {
    "exec": "validate_generated_code",
    "shell": "run_model_command",
    "sql": "validate_generated_sql",
    "http": "validate_outbound_url",
}
