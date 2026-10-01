"""SARIF 2.1.0 emitter.

SARIF is the interchange format every AppSec pipeline speaks; emitting it lets a
five-line GitHub Action put Palisade findings straight into the Security tab as
code-scanning alerts. Severity maps high->error, med->warning, low->note. The
sink is the primary location; source and LLM boundary are related locations.
Fingerprints are line-shift resilient, so alerts don't churn on refactors.

One exception to "the line is the line": a `.ipynb` finding's line is a line
of the reassembled notebook source, not of the JSON file on disk, so notebook
results are anchored at the file and carry the real line in the message and in
`properties["palisade/notebookSinkLine"]`. See `_location`.
"""

from __future__ import annotations

import json
import posixpath

from palisade_sec import __version__
from palisade_sec.engine import Finding, TracePoint
from palisade_sec.standards import label, owasp_url, sarif_cwe_tag, sarif_owasp_tag

_LEVEL = {"high": "error", "med": "warning", "low": "note"}
_INFO_URI = "https://github.com/arpankernel/palisade"


def _is_notebook(file: str) -> bool:
    return file.lower().endswith(".ipynb")


def _notebook_line_note(tp: TracePoint) -> str:
    """Short form, for the per-location role messages."""
    return f"reassembled notebook line {tp.line}"


def _notebook_result_note(tp: TracePoint) -> str:
    """Long form, once per result: says what the number means and why the
    alert is not pinned to a line of the file."""
    return (
        f"Notebook: line {tp.line} of the reassembled notebook source "
        "(`jupyter nbconvert --to script` numbering), not a line of the "
        ".ipynb file, which is JSON - so this alert is anchored at the file."
    )


def _uri(file: str, base_uri: str) -> str:
    """Make the artifact URI relative to the repository root.

    A finding's `file` is relative to the SCAN TARGET (scanning `src/` yields
    `foo.py`, not `src/foo.py`). GitHub code scanning resolves URIs against the
    repo root, so a subdirectory scan would place every alert at the wrong path.
    Prepending the scan base (relative to the repo root / cwd) fixes that."""
    if not base_uri or base_uri == ".":
        return file
    return posixpath.normpath(f"{base_uri}/{file}")


def _location(tp: TracePoint, role: str | None = None, base_uri: str = "") -> dict:
    """One SARIF location for a trace point.

    Notebooks are the one case where a finding's line is NOT a line of the
    file on disk. `.ipynb` is JSON; the line belongs to the reassembled cell
    source (see `frontends/notebook.py`). A single-line minified notebook has
    no line 12 at all, and a pretty-printed one has a line 12 pointing at
    arbitrary JSON metadata - a confidently wrong annotation, which is worse
    for a reviewer than none.

    So a notebook result is anchored at the file (`startLine: 1`) and the
    reassembled line is carried in the message instead. The region is *kept*
    rather than dropped: GitHub code scanning requires `region.startLine` and
    rejects the whole run without it, so one region-less result would discard
    every finding in the upload. `region.snippet` still carries the real sink
    text, so the alert names the code even though it cannot point at it.
    """
    notebook = _is_notebook(tp.file)
    loc: dict = {
        "physicalLocation": {
            "artifactLocation": {"uri": _uri(tp.file, base_uri)},
            "region": {
                "startLine": 1 if notebook else max(1, tp.line),
                "snippet": {"text": tp.snippet},
            },
        }
    }
    if role:
        text = f"{role}: {tp.snippet}".strip()
        if notebook:
            text = f"{text} [{_notebook_line_note(tp)}]"
        loc["message"] = {"text": text}
    return loc


def _message(f: Finding) -> str:
    parts = [f.title]
    if f.attack.strip():
        parts.append("Attack: " + f.attack.strip())
    if f.fix.strip():
        parts.append("Fix: " + f.fix.strip())
    if _is_notebook(f.sink.file):
        # The location cannot carry this (see `_location`), so the message
        # must, or the line number is simply lost to a SARIF consumer.
        parts.append(_notebook_result_note(f.sink))
    return "\n\n".join(parts)


def to_sarif(
    findings: list[Finding],
    tool_version: str | None = None,
    base_uri: str = "",
    *,
    files_scanned: int | None = None,
    notifications: list[str] | None = None,
) -> str:
    version = tool_version or __version__
    rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in rules:
            rule: dict = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            }
            # Standards metadata GitHub code scanning reads: CWE tags in its
            # `external/cwe/cwe-NNN` form, and security-severity, which ranks
            # the alert critical/high/medium in the Security tab.
            tags = ["security", *(sarif_cwe_tag(c) for c in f.cwe)]
            tags += [sarif_owasp_tag(o) for o in f.owasp_llm]
            props: dict = {"tags": tags, "precision": "high"}
            if f.security_severity is not None:
                props["security-severity"] = f"{f.security_severity:.1f}"
            rule["properties"] = props
            owasp = next((u for o in f.owasp_llm if (u := owasp_url(o))), None)
            if owasp or f.references:
                rule["helpUri"] = owasp or f.references[0]
            if f.cwe or f.owasp_llm:
                rule["fullDescription"] = {
                    "text": f"{f.title}. Maps to {label(f.cwe, f.owasp_llm)}."
                }
            rules[f.rule_id] = rule
    rule_index = {rid: i for i, rid in enumerate(rules)}

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": _message(f)},
                "locations": [_location(f.sink, base_uri=base_uri)],
                "relatedLocations": [
                    _location(f.source, "source", base_uri=base_uri),
                    _location(f.llm, "llm", base_uri=base_uri),
                ],
                "partialFingerprints": {"palisade/v1": f.fingerprint},
            }
        )
        if _is_notebook(f.sink.file):
            # Machine-readable twin of the message note, so a consumer does
            # not have to parse prose to recover the cell line.
            results[-1]["properties"] = {"palisade/notebookSinkLine": f.sink.line}

    run: dict = {
        "tool": {
            "driver": {
                "name": "palisade-sec",
                "informationUri": _INFO_URI,
                "version": version,
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }
    if files_scanned is not None or notifications:
        # Without an invocation record, an empty `results` array reads as a
        # clean run in GitHub code scanning even when nothing was checked.
        # Record whether the run examined anything and what it skipped.
        run["invocations"] = [
            {
                "executionSuccessful": files_scanned is None or files_scanned > 0,
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": n}} for n in notifications or []
                ],
            }
        ]
    return json.dumps(doc, indent=2)
