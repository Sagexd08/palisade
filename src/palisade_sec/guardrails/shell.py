"""Guardrail for PI-SHELL: LLM output about to reach a shell/subprocess sink.

Never hand model output to a shell. Parse it, allowlist the executable, and
run with an argument list (no shell=True) - Open Interpreter-style execution
without an allowlist is exactly this class of CVE.
"""

from __future__ import annotations

import shlex
import subprocess


class UnsafeCommandError(ValueError):
    """Raised when a model-proposed command's executable is not allowlisted."""


def run_model_command(
    command_line: str,
    allowed_executables: set[str],
    *,
    timeout: float = 10,
) -> subprocess.CompletedProcess[bytes]:
    """Run a model-proposed command line, allowlisted and without a shell.

    `allowed_executables` is required (no default allowlist ships with this
    guard - a real one must be chosen per call site, tightened to your
    actual needs). Raises UnsafeCommandError if the parsed executable is not
    in the allowlist. Never invoked with `shell=True`.
    """
    argv = shlex.split(command_line)
    if not argv or argv[0] not in allowed_executables:
        raise UnsafeCommandError(f"executable not allowed: {argv[:1]}")
    return subprocess.run(argv, shell=False, check=False, timeout=timeout)
