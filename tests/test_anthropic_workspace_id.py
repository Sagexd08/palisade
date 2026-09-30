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


def test_both_causes_of_a_400_get_named() -> None:
    """A 400 here means either "this key needs a workspace" or "that workspace
    id is wrong", and the response body distinguishes them only sometimes.

    The second case arrived in testing as a bare `HTTP 400: Bad Request`, which
    told the user nothing - the first version of this branch only fired when the
    body happened to contain the word "workspace". Both causes now get a
    concrete answer chosen by what was actually passed in.
    """
    import inspect

    src = inspect.getsource(connect_cli._verify_llm)
    assert "--workspace-id" in src, "the no-workspace case must name the flag that fixes it"
    assert "organization" in src
    assert "wrkspc_" in src, (
        "the wrong-id case must show what an id looks like - a user who passed a "
        "name or a placeholder cannot tell from `Bad Request`"
    )
    assert "if workspace_id:" in src, (
        "the two causes must be distinguished by whether an id was supplied, not "
        "by whether the provider's body happened to mention it"
    )


# ---------------------------------------------------------------------------
# The request body, and the error that hid why it failed
# ---------------------------------------------------------------------------


def test_the_request_does_not_send_temperature() -> None:
    """`audit` was completely broken against the default backend and
    `connect llm` still called the key verified.

    Current Claude models answer `temperature` with HTTP 400 - "`temperature`
    is deprecated for this model" - and the verify probe does not send it, so
    the probe passed and every real call failed. This is the same
    verifies-but-does-not-work divergence the header test guards, arriving
    through the body instead, which is why it is pinned here rather than left
    to a comment.
    """
    import inspect

    src = inspect.getsource(AnthropicBackend.ask)
    assert '"temperature"' not in src, (
        "sending temperature breaks audit on current models; it was removed "
        "deliberately, and the reproducibility it bought is noted in the code"
    )


def test_a_failure_carries_the_providers_reason() -> None:
    """`Anthropic returned HTTP 400.` with nothing else is what turned a
    one-line configuration bug into an unsearchable dead end."""
    from palisade_sec.judge.anthropic import _why

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def json(self):
            if self._payload is None:
                raise ValueError("not json")
            return self._payload

    assert _why(_Resp({"error": {"message": "`temperature` is deprecated"}})) == (
        "`temperature` is deprecated"
    )
    assert _why(_Resp(None)) == "no reason given"
    assert _why(_Resp({"nope": 1})) == "no reason given"


def test_the_reason_is_bounded_and_takes_only_the_message() -> None:
    """The message cannot contain the API key, but the surrounding body can
    echo the request - which carries the scanned code. So only `error.message`
    is read, and it is still bounded, because it is text from outside."""
    from palisade_sec.judge.anthropic import _why

    class _Resp:
        def json(self):
            return {"error": {"message": "x" * 5000}, "echo": {"messages": "SECRET CODE"}}

    out = _why(_Resp())
    assert len(out) <= 300
    assert "SECRET" not in out
