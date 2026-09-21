"""Guardrail for PI-SQL: LLM output about to reach a raw SQL sink.

Allow a single read-only statement, parsed with a real SQL parser rather than
string matching (Vanna.ai CVE-2024-5565 shipped a string-matching
"sanitizer" that a comment-based bypass defeated). Still execute on a
read-only connection/role and keep user-supplied VALUES parameterized -
this guard only bounds the statement shape, not connection privileges.

Needs the `sqlglot` extra: `pip install palisade-sec[guardrails-sql]`.
"""

from __future__ import annotations

try:
    import sqlglot
    from sqlglot import exp

    AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    AVAILABLE = False


class UnsafeSQLError(ValueError):
    """Raised when model-generated SQL is not a single SELECT statement."""


def validate_generated_sql(sql: str) -> str:
    """Validate model-generated SQL before execution.

    Raises UnsafeSQLError (a ValueError) unless `sql` parses as exactly one
    SELECT statement. Raises ImportError if the `guardrails-sql` extra is
    not installed.
    """
    if not AVAILABLE:
        raise ImportError("sqlglot not installed (pip install palisade-sec[guardrails-sql])")
    statements = sqlglot.parse(sql)
    if len(statements) != 1 or not isinstance(statements[0], exp.Select):
        raise UnsafeSQLError("only a single SELECT statement is allowed")
    return sql
