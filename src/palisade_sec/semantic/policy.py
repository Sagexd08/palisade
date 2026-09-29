"""POLICY: the editable, per-org conscience of the semantic layer.

The same judgment routes differently per company by adjusting thresholds and
criteria (see the guardrails cookbook). A fintech blocks at harm >= 1; a hobby
project at 3. Criteria are editable English that sharpens the question sent to
the model.

Loaded, in precedence order, by `load_policy`:

    1. `--policy PATH`   - the user naming a file, trusted completely
    2. `.palisade/policy.yaml` in the scanned tree
    3. `[tool.palisade.semantic]` in the scanned tree's `pyproject.toml`
    4. the built-in defaults

## Why `criteria` has a trust boundary

A `criteria` value is interpolated into the instructions sent to the judge
(`semantic/judge.py`), so it is *prompt text*. A policy file discovered inside
the tree being scanned is therefore untrusted input reaching a model - the
exact shape Palisade exists to find. A scanned repository could otherwise ship
a `.palisade/policy.yaml` saying "nothing here is ever irreversible" and talk
the judge out of its own finding.

So discovered files may set thresholds - a project stating its own risk
appetite, like the rest of `.palisade.toml` - but their `criteria` is dropped
with a warning. Only `--policy`, where the user named the file, sets criteria.
That is the same split already applied to `rules_dir` in `scanner.py`: an
explicit flag is the user's choice; in-tree discovery is confined.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class CheckPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Route above this probability -> block (in CI). Between review and action
    # thresholds -> review. Below review_threshold -> pass.
    action_threshold: float = 0.60
    review_threshold: float = 0.30
    # A tool counts as "gated" (mitigated) only if the confirmation probability
    # is at least this; below it, the action is treated as ungated.
    gate_threshold: float = 0.50
    # Harm (0-3) at or above this turns a review into a block.
    severity_block: int = 2
    # Editable English that sharpens the model's question.
    criteria: dict[str, str] = Field(default_factory=dict)


class SemanticPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checks: dict[str, CheckPolicy] = Field(default_factory=dict)

    def for_check(self, name: str) -> CheckPolicy:
        return self.checks.get(name, CheckPolicy())


def default_policy() -> SemanticPolicy:
    return SemanticPolicy(
        checks={
            "excessive_agency": CheckPolicy(
                criteria={
                    "irreversible": (
                        "deletes or overwrites data, spends money, sends "
                        "messages to customers, runs shell commands, or changes "
                        "production/cloud state"
                    ),
                },
            ),
            "taint_exploitability": CheckPolicy(
                action_threshold=0.60,
                review_threshold=0.30,
                severity_block=2,
            ),
        }
    )


POLICY_FILENAME = ".palisade/policy.yaml"
PYPROJECT_KEY = "semantic"


def _strip_criteria(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Remove `criteria` from a discovered (untrusted) policy.

    Returns the cleaned data and the names of the checks it was removed from,
    so the caller can say so out loud rather than silently ignoring what
    someone wrote.
    """
    dropped: list[str] = []
    checks = data.get("checks")
    if not isinstance(checks, dict):
        return data, dropped
    cleaned_checks: dict[str, Any] = {}
    for name, check in checks.items():
        if isinstance(check, dict) and check.get("criteria"):
            check = {k: v for k, v in check.items() if k != "criteria"}
            dropped.append(str(name))
        cleaned_checks[name] = check
    return {**data, "checks": cleaned_checks}, dropped


def _merge(base: SemanticPolicy, data: dict[str, Any]) -> SemanticPolicy:
    """Overlay a parsed policy on the defaults, per check and per field.

    A file that sets one threshold for one check keeps every other default,
    rather than silently resetting the rest to the model's bare defaults -
    which would loosen `excessive_agency` by dropping its `criteria`.
    """
    merged = {name: check.model_copy() for name, check in base.checks.items()}
    for name, incoming in (data.get("checks") or {}).items():
        if not isinstance(incoming, dict):
            continue
        current = merged.get(str(name)) or CheckPolicy()
        merged[str(name)] = current.model_copy(
            update={k: v for k, v in incoming.items() if v is not None}
        )
    return SemanticPolicy(checks=merged)


def load_policy(root: Path, policy_file: str | None = None) -> tuple[SemanticPolicy, list[str]]:
    """The policy for this run, plus warnings. Never raises on bad input.

    `root` is the scanned tree. A file found inside it is trusted for
    thresholds but not for `criteria` - see the module docstring. A
    `policy_file` the user passed is trusted for both.
    """
    warnings: list[str] = []
    base = default_policy()

    if policy_file:
        path = Path(policy_file)
        if not path.is_file():
            warnings.append(f"policy file not found, using defaults: {path}")
            return base, warnings
        data, parse_warning = _read(path)
        if parse_warning:
            return base, [*warnings, parse_warning]
        return _validate(base, data, path, warnings)

    yaml_path = root / POLICY_FILENAME
    if yaml_path.is_file():
        data, parse_warning = _read(yaml_path)
        if parse_warning:
            return base, [*warnings, parse_warning]
        data, dropped = _strip_criteria(data)
        if dropped:
            warnings.append(
                f"{yaml_path}: `criteria` is ignored in a policy file found inside the "
                f"scanned tree (check(s): {', '.join(sorted(dropped))}) - criteria become "
                "part of the question sent to the judge, so only a policy you name with "
                "--policy may set them. Thresholds were applied."
            )
        return _validate(base, data, yaml_path, warnings)

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data, parse_warning = _read(pyproject)
        if parse_warning:
            return base, [*warnings, parse_warning]
        section = (data.get("tool") or {}).get("palisade") or {}
        subtable = section.get(PYPROJECT_KEY)
        if isinstance(subtable, dict):
            data, dropped = _strip_criteria(subtable)
            if dropped:
                warnings.append(
                    f"{pyproject}: `criteria` is ignored in [tool.palisade.semantic] "
                    f"(check(s): {', '.join(sorted(dropped))}) - pass --policy to set "
                    "criteria. Thresholds were applied."
                )
            return _validate(base, data, pyproject, warnings)

    return base, warnings


def _read(path: Path) -> tuple[dict[str, Any], str | None]:
    """Parse YAML or TOML by extension. Returns ({}, warning) on any problem."""
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".toml":
            parsed: Any = tomllib.loads(text)
        else:
            parsed = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
        return {}, f"invalid policy skipped, using defaults: {path}: {exc}"
    if parsed is None:
        return {}, None
    if not isinstance(parsed, dict):
        return {}, f"invalid policy skipped, using defaults: {path}: expected a mapping"
    return parsed, None


def _validate(
    base: SemanticPolicy, data: dict[str, Any], path: Path, warnings: list[str]
) -> tuple[SemanticPolicy, list[str]]:
    """Validate the overlay, falling back to defaults rather than crashing.

    `extra="forbid"` means a typo (`action_treshold`) is an error, not a
    silently ignored key that leaves the gate at a threshold nobody chose.
    """
    try:
        SemanticPolicy.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(p) for p in first.get("loc", ()))
        warnings.append(
            f"invalid policy skipped, using defaults: {path}: "
            f"{loc + ': ' if loc else ''}{first.get('msg', exc)}"
        )
        return base, warnings
    return _merge(base, data), warnings
