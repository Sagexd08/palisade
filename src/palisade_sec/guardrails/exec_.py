"""Guardrail for PI-EXEC: LLM output about to reach exec/eval/compile.

Strict AST allowlist. Anything outside it is rejected - never a denylist,
never a human-confirmation gate alone; both were bypassed in real CVEs
(PandasAI CVE-2024-12366, Langflow CVE-2025-3248).
"""

from __future__ import annotations

import ast

ALLOWED_NODES: tuple[type[ast.AST], ...] = (
    ast.Module,
    ast.Expr,
    ast.Expression,
    ast.Assign,
    ast.Call,
    ast.Name,
    ast.Load,
    ast.Store,
    ast.Constant,
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Tuple,
    ast.List,
    ast.Dict,
    ast.keyword,
)

DISALLOWED_NAMES: frozenset[str] = frozenset({"eval", "exec", "__import__", "open"})


class UnsafeCodeError(ValueError):
    """Raised when model-generated code falls outside the AST allowlist."""


def validate_generated_code(code: str) -> str:
    """Validate model-generated Python before it is ever executed.

    Parses `code` and rejects it if any node type or name is outside the
    allowlist. Callers must still execute the result with an empty
    `__builtins__` and prefer a sandboxed subprocess/container with no
    network - this function only bounds the *syntax*, not the runtime.

    Raises UnsafeCodeError (a ValueError) if `code` is unsafe.
    """
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise UnsafeCodeError(f"disallowed construct: {type(node).__name__}")
        if isinstance(node, ast.Name) and node.id in DISALLOWED_NAMES:
            raise UnsafeCodeError(f"disallowed name: {node.id}")
    return code
