# Recall protocol: how to make the number falsifiable

Precision is measured against 18 clean repos that must stay silent, gated in
CI, and it has held at **1.000**. Recall has no equivalent discipline. It is
currently **0.200** over **10 hand-verified paths in 8 repos**, and the next
engine work is aimed squarely at the 8 it misses.

That is the problem this document exists to prevent. Fixing the eight misses
you can read in a table and then publishing the resulting recall is fitting to
the test set: the number goes up, the tool does not get better, and the first
person who runs it on repo #27 finds out.

## The rule, in one line

> **A recall number is only publishable if it was measured on paths whose
> misses had never been diagnosed in writing before the fix was designed.**

Everything below follows from that.

## What actually leaks a held-out set

Not reading `corpus/repos.yaml`. The label says *where* a vulnerability is; it
does not say why the engine misses it. The engine is fixed against the
**diagnosis**, not the location.

So the leak is `docs/proof-scans.md`:

| Repo | Why it is missed |
|---|---|
| crewai-tools | tool-call arguments are not modeled as model output |
| autogen | `model_client.create` not recognized; abstract executor methods |
| dspy | dspy module calls are not recognized as LLM calls |

Those sentences are the specification for gaps 1 and 2. Once written, the path
is a training example forever.

**Therefore the discipline is about writing, not reading.** A held-out miss may
be *counted*. It may not be *explained* - not in `proof-scans.md`, not in a
commit message, not in a roadmap entry, not in a PR comment - until it has been
retired from the held-out set.

## Consequence: the existing 10 paths are burned

All 10 current paths are training data, permanently. Their diagnoses are
published. No future fix can claim them as held-out evidence, and they must not
be moved.

The held-out set has to be built from **newly labelled paths only**, and each
one has to be assigned to a split **before anyone scans the repo it lives in**.

## Labelling schema

Unchanged from what `scripts/precision.py` already reads, plus one field:

```yaml
- name: some-repo
  url: https://github.com/org/some-repo
  ref: v1.2.3              # a tag or SHA; corpus/fetch.py pins the exact commit
  kind: audited            # cve | patched | audited | clean
  library_mode: true       # when public function params are the untrusted source
  split: held-out          # train | held-out    <- new, see below
  expect:
    - file: src/pkg/tools.py
      line: 214
      rule: PI-SQL
      verdict: flag        # `flag` counts toward recall; anything else is a note
      code: "cur.execute(sql)"   # the exact sink text at the pinned ref
```

Rules for a label to count:

1. **Verified at the pinned ref.** The `code` string must appear at
   `file:line` in that exact commit. `tests/test_fp_regressions.py` checks
   this, so a drifting label fails rather than silently mis-scoring.
2. **A real path, not a shape.** Untrusted input must actually reach the sink
   through a model in that repo's own code. Record the mitigation (`sandboxed
   by default`, `prompt text only`, `none`) - mitigated paths still count as
   misses, they just rank lower.
3. **One label per sink site.** Not per rule that could match it.

## The split rule

- **Assign by repo, never by path.** Two paths in the same repo share idioms,
  framework, and often the same missing call shape. Splitting within a repo
  leaks the diagnosis across the boundary.
- **Assign before scanning.** The order is: pick the repo, pin the ref, assign
  the split, *then* audit and label. Assigning after a scan means the
  assignment is informed by what was found.
- **One-way door.** A path may move `held-out` -> `train` (retiring it, which
  permits writing its diagnosis). It may **never** move `train` -> `held-out`,
  and a `held-out` path may never be reassigned *after* a miss is observed.
- **Retire deliberately, in batches.** When a gap is closed and its held-out
  evidence has been spent, retire those repos to `train` in one commit that
  says so. Recall is then re-measured on what remains held-out.

## When one agent both labels and fixes

The held-out set exists to neutralize a conflict of interest. If the same
person (or agent) labels the held-out paths and then fixes the engine against
them, that conflict is back inside one head, and the split protects nothing.

Three rules stand in for a second person. They are not advice; two of them are
tested.

### 1. The freeze is a commit, not an intention

The order is: **assign the split -> commit -> then look.**

Assignment happens before the repo is investigated at all, not merely before it
is scanned. If you read the source first, find a path, and think "this looks
like something the engine would miss", the assignment you then make is
informed - and an informed assignment is not a held-out set. Splits are
therefore assigned by a recorded, seeded shuffle over repo names, committed on
their own, and only then is anything read or scanned.

If the split assignment and the first scan of a repo happen in one working
session with no commit between them, the freeze is on the honour system.

### 2. Held-out labels carry location, never diagnosis

A held-out label may record `file`, `line`, `rule`, `verdict` and the exact
`code` at the pinned ref. That is what the scorer matches and what the drift
test checks.

It may **not** record why the engine misses it. Not in a YAML comment, not in
`docs/proof-scans.md`, not in a commit message, not in a PR description. The
moment that sentence exists, it is the specification for the fix, and the path
is training data.

Compare the existing train labels, which are correctly verbose:

```yaml
# MITIGATED (Docker executor by default...): CodeExecutorAgent runs model code.
# Missed: model_client.create not recognized; abstract executor method.
```

That second line is exactly what a held-out label must not have. **If you find
yourself wanting to write down the cause of a held-out miss, that is the signal
to stop.** Count it, name nothing, move on.

`tests/test_recall_protocol.py` fails if a held-out entry's comments contain
diagnosis-shaped language.

### 3. Labelling and fixing are separate passes

Label, freeze, commit. Then, in a later pass, fix the engine and measure
against the frozen set.

Interleaving them means seeing a held-out miss while still holding the freedom
to relabel - at which point the wall between ground truth and the fix is gone,
whatever anyone intended. Two passes, a commit between.

## Targets

| | Now | Target |
|---|---|---|
| Labelled paths | 10 | ~40 |
| Repos carrying labels | 8 | ~20 |
| Held-out paths | 0 | >= 15, across >= 6 repos |

18 of the 26 repos carry no labels at all today; they are precision ballast.
Several almost certainly contain real paths nobody has looked for.

## Measurement protocol

`scripts/precision.py` reports three numbers, and only one of them is
publishable:

| Number | Meaning | Publishable |
|---|---|---|
| `recall(train)` | on paths whose misses are documented | **no** - fit to it by construction |
| `recall(held-out)` | on paths never diagnosed in writing | **yes** - this is the number |
| `recall(all)` | both pooled | only alongside the split |

Precision is unaffected: a false positive is a false positive wherever it
appears, and every clean repo stays in the precision gate regardless of split.

**The CI gate stays on precision only.** Gating on held-out recall would create
pressure to retire paths to make the build green, which is the same failure in
a different costume.

## Reporting rules

- Publish `recall(held-out)` with its `tp`/`fn` and the repo count. A number
  from n=15 is a weak estimate and should say so.
- The miss table in `docs/proof-scans.md` lists **train paths only**. A
  held-out miss appears as a count, with no repo name and no reason.
- When recall improves, say which half it was measured on. "Recall rose to 0.5"
  measured on train is not a result.

## Vacuity guards

The harness already fails a `cve`/`audited` repo that mints zero untrusted
sources, and warns when a clean repo is unchallenged. Two more belong here:

- **An empty held-out set is a failure, not a pass.** `recall(held-out)` over
  zero paths must report `n/a` and never `1.000`.
- **A split that drifts is a failure.** If a repo's `split` changes from
  `held-out` to anything else in a commit that also touches `src/`, that is the
  one-way door being walked backwards. Worth a check.
