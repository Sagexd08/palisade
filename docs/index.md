# Palisade documentation

> Rendered and searchable at **https://try.arpankernel.com/docs/** - this directory is the source.

**We are building the AI safety engineer for your codebase.** The complete role
is the destination; one verb of it ships today.

**v1, live now:** a precise static detector for prompt-injection-to-execution
paths - untrusted input reaches a model, and the model's output reaches `exec`,
a shell, raw SQL, a model-chosen URL, or a dangerous tool across an agent
handoff. Python and JavaScript/TypeScript, in CI, with no API key and no
network calls.

**Measured in both directions, and never one without the other:** precision
**1.000** (zero false positives across 40,466 files in 50 repos) and held-out
recall **0.000** (0 of 45 independent observations in 20 repos). Ground-truth
denominators are known-incomplete, so that recall figure is, if anything, an
overestimate. Palisade **does not yet catch tool-calling agent frameworks** -
the shape where a framework hands model-chosen arguments to a tool it ships
across an object boundary. That limit is measured, documented, and named on the
roadmap as the next capability.

The rest of the role - probing the system adversarially, generating guardrails
and safety cases, watching production - is upcoming, marked as such, with no
dates.

```
untrusted input  →  LLM  →  exec / shell / raw SQL / URL fetch   (no sanitizer)   ⇒  finding
```

## Where to go

| Document | What it covers | Read it when |
|---|---|---|
| [Getting started](getting-started.md) | Install, first scan, reading a finding, exit codes | You have 5 minutes |
| [End-to-end tutorial](tutorial.md) | A full workflow on a sample app: scan → understand → fix → verify → baseline → CI → library mode → JS | You're adopting Palisade on a real project |
| [Architecture](architecture.md) | Frontends → taint IR → engine → rules; how a finding is born; the precision philosophy; the safety contract | You're contributing, or evaluating how it works |
| [CLI reference](cli-reference.md) | Every command, flag, exit code, config key, the JSON schema, the baseline format | You're wiring it into tooling |
| [Rules reference](rules-reference.md) | All six builtin rules in depth; pattern semantics; sanitizer tiers; writing custom rules | You're tuning or extending coverage |
| [For AI agents](agents.md) | A machine-oriented contract: exact commands, JSON parsing, pass/fail policy, remediation loop | You're an agent - or you're pointing one at Palisade |
| [Roadmap](roadmap.md) | Phases 0–6 (Measure → Remediate), the sequencing thesis, current status per phase | You want to know where this is going |
| [Proof scans](proof-scans.md) | Palisade vs. the real CVE repos - hits, misses, and what each miss taught the engine | You want the evidence |

Related, outside `docs/`:

- [`README.md`](../README.md) - the front page.
- [`examples/support-bot/`](../examples/support-bot/) - the tutorial's sample app.
- [`examples/vulnerable-app/`](../examples/vulnerable-app/) - the acceptance fixtures (every behavior claim in these docs is pinned by a test against this app).
- [`src/palisade_sec/rules/README.md`](../src/palisade_sec/rules/README.md) - the 5-minute "add a rule" guide.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) · [`CHANGELOG.md`](../CHANGELOG.md) · [`AGENTS.md`](../AGENTS.md) (repo-level agent instructions) · [`llms.txt`](../llms.txt)

## The one-paragraph mental model

Palisade parses your source (never executes it), lowers it into a
language-neutral taint IR, and propagates taint from **sources** (request
fields, CLI args, route params, library params) through **LLM call sites**
into **sinks** (`exec`, shells, raw SQL, URL fetches). A finding requires the
*complete* source → LLM → sink path with no real sanitizer in between -
that's why it stays quiet on constant prompts, parameterized queries, and
arg-list subprocess calls, and why a denylist or a cosmetic "sanitizer"
downgrades a finding instead of silencing it. Rules are YAML data; adding
coverage never requires engine changes.
