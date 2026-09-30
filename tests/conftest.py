import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_APP = REPO_ROOT / "examples" / "vulnerable-app"

sys.path.insert(0, str(REPO_ROOT / "src"))

from palisade_sec.judge import config as _jconfig  # noqa: E402

# The real .env reader, kept for the tests that exercise it; every other test
# sees an empty .env (see _never_read_a_real_dotenv).
REAL_DOTENV_VALUES = _jconfig._dotenv_values
# Likewise for the keychain reader (see _never_read_the_real_keychain): the
# tests that assert stored credentials configure the judge need the real one.
REAL_STORED_JUDGE_SETTINGS = _jconfig._stored_judge_settings


@pytest.fixture(autouse=True)
def _never_read_a_real_dotenv(monkeypatch):
    """The judge config reads `.env` from the working directory and its
    parents. A developer's real .env (with live keys) must never leak into
    the suite and trigger network calls; tests that exercise .env loading
    patch this themselves."""
    from palisade_sec.judge import config as jconfig

    monkeypatch.setattr(jconfig, "_dotenv_values", lambda: {})


@pytest.fixture(autouse=True)
def _never_read_the_real_keychain(monkeypatch):
    """The same hazard as `.env`, one door along, and it was open.

    `get_backend()` also merges settings stored in the OS keychain by
    `palisade-sec connect llm`. So the suite's result depended on whether the
    developer running it happened to have a provider connected: green in CI,
    which has no keychain, and eight failures on a machine where someone had
    connected a real key - failures with nothing to do with their change.

    A test suite that reads the developer's live credentials is a suite that
    reports on the machine instead of the code. Tests that exercise stored
    settings patch this themselves.
    """
    from palisade_sec.judge import config as jconfig

    monkeypatch.setattr(jconfig, "_stored_judge_settings", lambda: {})


@pytest.fixture(scope="session")
def example_scan():
    from palisade_sec.scanner import run_scan

    return run_scan(EXAMPLE_APP)


def find_line(file: Path, needle: str, after: str | None = None) -> int:
    """1-based line number of the first line containing `needle`, optionally
    only after the first line containing `after` (e.g. a def line)."""
    lines = file.read_text().splitlines()
    start = 0
    if after is not None:
        for i, line in enumerate(lines):
            if after in line:
                start = i + 1
                break
        else:
            raise AssertionError(f"marker {after!r} not found in {file}")
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    raise AssertionError(f"{needle!r} not found in {file} after {after!r}")


def func_range(file: Path, def_name: str) -> tuple[int, int]:
    """(start, end) 1-based line range of a top-level function body."""
    lines = file.read_text().splitlines()
    start = None
    for i, line in enumerate(lines):
        if start is None:
            if line.startswith(f"def {def_name}(") or f"def {def_name}(" in line:
                start = i + 1
        else:
            if line and not line[0].isspace() and not line.startswith(("@", ")")):
                return start, i
    if start is None:
        raise AssertionError(f"def {def_name} not found in {file}")
    return start, len(lines)
