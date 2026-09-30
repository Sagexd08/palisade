"""An organization-scoped Anthropic key needs a workspace id.

Found by running the release checklist on a real key, which is the only way it
could have been found: every existing test used a workspace-scoped key or a
mock, so the header was never missing in a way anything noticed. The provider
answers HTTP 400 with an instruction, and our 200-character body excerpt cut it
mid-sentence, so the user saw neither a working key nor a complete reason.

The property that matters most here is not the header. It is that the probe and
the judge backend send the SAME headers: if they drift, a key that verifies is
not a key that works, and `connect llm` becomes a green light for a runtime
failure - the false-green shape, one layer down.
"""

from __future__ import annotations

from palisade_sec.connect import cli as connect_cli
from palisade_sec.connect import store
from palisade_sec.judge.anthropic import API_VERSION, AnthropicBackend


def test_the_header_is_sent_when_a_workspace_is_configured() -> None:
    headers = connect_cli._anthropic_headers("sk-test", "wrk_123")
    assert headers["anthropic-workspace-id"] == "wrk_123"
    assert headers["x-api-key"] == "sk-test"
    assert headers["anthropic-version"] == API_VERSION


def test_the_header_is_absent_when_there_is_no_workspace() -> None:
    """A workspace-scoped key must not carry an empty header: Anthropic rejects
    a blank value, so sending one would break the case that works today."""
    assert "anthropic-workspace-id" not in connect_cli._anthropic_headers("sk-test", None)
    assert "anthropic-workspace-id" not in connect_cli._anthropic_headers("sk-test", "")


def test_the_probe_and_the_backend_agree() -> None:
    """The load-bearing test. Two code paths build Anthropic headers, and if
    they diverge then `connect llm` verifies a key that `audit` cannot use."""
    probe = connect_cli._anthropic_headers("sk-test", "wrk_123")
    backend = AnthropicBackend(api_key="sk-test", workspace_id="wrk_123")._headers()
    for name in ("x-api-key", "anthropic-version", "anthropic-workspace-id"):
        assert probe[name] == backend[name], f"{name} differs between probe and backend"


def test_the_backend_omits_the_header_by_default() -> None:
    assert "anthropic-workspace-id" not in AnthropicBackend(api_key="sk-test")._headers()


def test_the_workspace_id_is_not_treated_as_a_secret() -> None:
    """It is an identifier, and `connections` should show it. Putting it in the
    secret set would redact the one field that tells a user which workspace
    their judged findings were billed and scoped to."""
    assert store.LLM_WORKSPACE not in store._SECRET_KEYS


def test_disconnecting_llm_clears_the_workspace_id() -> None:
    """A stale workspace id outliving its key would be sent with the next one,
    which is a confusing 400 for a reason the user already fixed."""
    import inspect

    src = inspect.getsource(connect_cli.disconnect_cmd)
    assert "LLM_WORKSPACE" in src, "disconnect llm must clear the workspace id too"


def test_the_organization_key_error_names_the_fix() -> None:
    """The provider's own message says what to do and our body excerpt cut it
    in half. The advice has to come from us, not from a fragment."""
    import inspect

    src = inspect.getsource(connect_cli._verify_llm)
    assert "--workspace-id" in src, "the 400 branch must name the flag that fixes it"
    assert "organization key" in src
