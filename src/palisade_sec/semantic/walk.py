"""Shared IR traversal for the semantic layer.

Small, total over the node vocabulary in ir/model.py. Both the PROBE (tool
harvesting) and the MAP (AI-surface inventory) walk the IR the same way.
"""

from __future__ import annotations

from collections.abc import Iterator

from palisade_sec import ir


def iter_call_exprs(expr: ir.Expr | None) -> Iterator[ir.Call]:
    """Yield every Call reachable from an expression (including nested)."""
    if expr is None:
        return
    if isinstance(expr, ir.Call):
        yield expr
        for a in expr.args:
            yield from iter_call_exprs(a)
        for v in expr.kwargs.values():
            yield from iter_call_exprs(v)
        for s in expr.star_args:
            yield from iter_call_exprs(s)
        yield from iter_call_exprs(expr.receiver)
    elif isinstance(expr, ir.Member):
        yield from iter_call_exprs(expr.base)
    elif isinstance(expr, ir.StrJoin):
        for p in expr.parts:
            yield from iter_call_exprs(p)
    elif isinstance(expr, ir.Collection):
        for it in expr.items:
            yield from iter_call_exprs(it)
    elif isinstance(expr, ir.Unknown):
        for c in expr.children:
            yield from iter_call_exprs(c)


def iter_calls(stmts: list[ir.Stmt]) -> Iterator[ir.Call]:
    """Yield every Call reachable from a statement list (recursing bodies)."""
    for st in stmts:
        if isinstance(st, ir.Assign):
            yield from iter_call_exprs(st.value)
        elif isinstance(st, ir.ExprStmt):
            yield from iter_call_exprs(st.value)
        elif isinstance(st, ir.Return):
            yield from iter_call_exprs(st.value)
        elif isinstance(st, ir.IfBranch):
            yield from iter_call_exprs(st.test)
            yield from iter_calls(st.body)
            yield from iter_calls(st.orelse)
        elif isinstance(st, ir.ForLoop):
            yield from iter_call_exprs(st.iter)
            yield from iter_calls(st.body)
        elif isinstance(st, ir.WhileLoop):
            yield from iter_calls(st.body)
        elif isinstance(st, ir.TryBlock):
            yield from iter_calls(st.body)
            for h in st.handlers:
                yield from iter_calls(h)
            yield from iter_calls(st.finalbody)
        elif isinstance(st, ir.WithBlock):
            for _name, e in st.items:
                yield from iter_call_exprs(e)
            yield from iter_calls(st.body)


def module_calls(mod: ir.Module) -> Iterator[ir.Call]:
    """Every Call in a module - inside functions and at module top level."""
    for fn in mod.functions:
        yield from iter_calls(fn.body)
    if mod.toplevel is not None:
        yield from iter_calls(mod.toplevel.body)


def iter_calls_with_guards(
    stmts: list[ir.Stmt], guards: tuple[ir.IfBranch, ...] = ()
) -> Iterator[tuple[ir.Call, tuple[ir.IfBranch, ...]]]:
    """Like `iter_calls`, but also yields the stack of enclosing `IfBranch`
    nodes a call sits inside - innermost last. Used to tell whether a
    dangerous call is unconditional or sits behind a guard, and to recover
    the guard's condition text (`IfBranch.loc.snippet`) as evidence.

    A call in `test`/`iter`/`items` (the branch condition itself, not its
    body) is NOT considered guarded by that branch - only calls inside
    `body`/`orelse` are. A call in `orelse` is guarded by the *negation* of
    the test, but callers needing that distinction should check
    `IfBranch.negated` themselves; this only tracks nesting.

    In practice a call inside an `if`'s own test expression is rarely
    reachable here at all: the Python frontend lowers `IfBranch.test` to a
    placeholder and keeps the guard's real content as dotted-path strings in
    `test_names`/`test_calls`, not as a walkable `Expr` - so `iter_call_exprs`
    over `test` yields nothing for the common case. This is a property of
    the IR, not of this walk.
    """
    for st in stmts:
        if isinstance(st, ir.Assign):
            for c in iter_call_exprs(st.value):
                yield c, guards
        elif isinstance(st, ir.ExprStmt):
            for c in iter_call_exprs(st.value):
                yield c, guards
        elif isinstance(st, ir.Return):
            for c in iter_call_exprs(st.value):
                yield c, guards
        elif isinstance(st, ir.IfBranch):
            for c in iter_call_exprs(st.test):
                yield c, guards
            yield from iter_calls_with_guards(st.body, guards + (st,))
            yield from iter_calls_with_guards(st.orelse, guards + (st,))
        elif isinstance(st, ir.ForLoop):
            for c in iter_call_exprs(st.iter):
                yield c, guards
            yield from iter_calls_with_guards(st.body, guards)
        elif isinstance(st, ir.WhileLoop):
            yield from iter_calls_with_guards(st.body, guards)
        elif isinstance(st, ir.TryBlock):
            yield from iter_calls_with_guards(st.body, guards)
            for h in st.handlers:
                yield from iter_calls_with_guards(h, guards)
            yield from iter_calls_with_guards(st.finalbody, guards)
        elif isinstance(st, ir.WithBlock):
            for _name, e in st.items:
                for c in iter_call_exprs(e):
                    yield c, guards
            yield from iter_calls_with_guards(st.body, guards)
