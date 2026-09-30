# Recall protocol: how to make the number falsifiable

Precision is measured across all 26 corpus repos - every HIGH finding that is
not a recorded label counts against it, in an audited repo as much as in a
clean one - and it has held at **1.000**. Recall had no equivalent discipline.
It was **0.200** over **10 hand-verified paths in 8 repos**, all of them train,
and the next engine work is aimed squarely at the 8 it misses.

**Measured under this protocol on 2026-09-30, after the corpus grew to 50
repos: held-out recall 0.000.**

| denominator | result |
|---|---|
| paths | 0 / 98 |
| groups as labelled (by blind labellers) | 0 / 74 |
| groups per capability (pessimistic bound) | **0 / 45** |
| repos carrying held-out labels | 20 |

The first measurement, at n=6, was too small to distinguish a poor engine from
an unlucky draw. This one is not. Zero hits out of 45 independent observations
puts the 95% upper bound near **0.07**: the engine finds essentially none of the
real injection-to-capability paths in modern agent frameworks, and that is now a
finding rather than a weak estimate.

Precision over the same run is **1.000 with zero false positives across 40,466
files**. Those two numbers have to be quoted together, always. A detector that
reports nothing has perfect precision trivially, and this harness exists to
refuse exactly that kind of vacuity - it has to refuse it for the product too,
not only for the corpus.

That is the problem this document exists to prevent. Fixing the eight misses
you can read in a table and then publishing the resulting recall is fitting to
the test set: the number goes up, the tool does not get better, and the first
person who runs it on repo #27 finds out.

## Ground truth is known-incomplete, and that biases recall upward

On 2026-09-30 the engine reported a sink in `crewai` that carried no label. It
was not a false positive: `singlestore_search_tool.py:399` hands a tool
argument straight to `cursor.execute`, and the tool's own docstring calls it
"The SQL query to execute". It is a **sibling** of an existing label - same
shape, same directory - and reading the family by hand turned up a second one
(`nl2sql_tool.py:486`).

That is not two missing labels. It is evidence about the whole corpus:

> **The train side has undercounted real paths, so train recall has been
> measured against an incomplete denominator from the beginning. The held-out
> side is labelled by the same kind of pass and is very likely undercounted
> too. Every recall figure this project publishes is therefore, if anything, an
> OVERESTIMATE: the numerator is what the engine found, and the denominator is
> smaller than the truth.**

The held-out undercount cannot be corrected. Hand-auditing held-out families
now would be relabelling after measurement, which is the one-way door walked
backwards, and it would be done with the engine's output in view. So it stands
as a recorded limitation rather than a fixed defect.

Two things follow, and both are permanent:

- **A recall figure is an upper bound on a lower bound.** Quote it as measured,
  never as "the recall", and never argue from it that a repo is clean.
- **A found-but-unlabelled sink is triage, not a false positive, until a human
  reads it.** `scripts/precision.py --triage` exists for exactly this, and the
  outcome is recorded in the manifest with its provenance - including which
  labels were added because the engine pointed at them.

Said plainly because a reviewer will otherwise find an unlabelled sibling and
conclude the benchmark is sloppy. It is incomplete, the incompleteness is
directional, and the direction is against us.

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

## Labelling criteria

A candidate becomes a label only if all four hold. They are written out because
the next pass may be a different session, and ground truth that shifts between
batches is the same failure as fitting to the test set, arriving more slowly.

### 1. The wiring is in this repo

Untrusted text must reach the dangerous capability through code **in the repo
being scanned**. Shipping a dangerous tool for an adopter to register is not
enough: the wiring then lives in the adopter's repo, which is the thing Palisade
would be pointed at.

| Kept | Rejected |
|---|---|
| pydantic-ai `data_analyst.py` - the agent, the `@tool` registration and the DuckDB call are all in this repo | Semantic Kernel `http_plugin.py` - the plugin performs the request, but the model output reaches it only once an adopter registers it with a kernel |
| litellm `sandbox_executor.py` - `acompletion` -> tool-call `arguments["code"]` -> sandbox run, every hop in-repo | Haystack `LinkContentFetcher` - a public fetch method with no in-repo path from any model output to it |
| swarm `local_engine.py` - the planner's LLM call and the module load it drives are in the same file | swarm `core.py` - the dispatch is real, but every function it can reach is caller-supplied |

The test is not "could this be exploited?" - it is "is the exploitable
arrangement present here?" Flagging the rejected column would be a false
positive against a framework doing its job, so a label there would encode a
false positive as ground truth.

### 2. One label per mechanism, and correlated paths grouped

Sibling methods of one class are one mechanism at several sites. Labelling each
inflates `n` while making the estimate worse: they move together, so one
behaviour swings the number by 4/n.

Where several paths in one repo genuinely differ but still move together - a
planner that reaches a capability three ways is found three times or not at all
- they carry the same `group:` tag and the harness reports an **effective n**
alongside the raw count. A held-out set of 18 paths where 12 are correlated is
worth about 8 independent observations, and quoting 18 overstates the
estimate's power by more than a factor of two.

`group:` is an **opaque tag** - `a`, `b`, never "planner reaches exec via
importlib". It records *that* two paths move together, never *how*, because how
is the diagnosis. A label with no group is its own group: defaulting to a
shared group would shrink the denominator, which raises recall, which is the
direction that flatters.

### 3. The sink is the earliest line at which the capability is exercised

On model-derived data. Where a flow loads an attacker-named module and then
calls into it, the label goes on the load.

*Disclosed:* not score-neutral - it tends to pick the more recognisable of two
adjacent lines. Fixed before measurement and applied where it costs.

### 4. The bar does not move for the target (no test, by design)

The bar that turned 15 candidates into 6 is the bar. If a batch yields 9 real
paths across 5 repos, the number is 9, and the response is to assign more
repos - never to loosen criterion 1 once a number is in. That is the one-way
door walked backwards, and it is the most tempting version of it, because
loosening it would look like a methodology refinement rather than a retreat.

This one is prose and stays prose. The violation is a rationalization, not a
state a test can read: by the time the criterion has been loosened, the corpus
looks internally consistent and every label passes. Writing down which
direction the pressure comes from is the whole of the enforcement available,
and a test that pretended otherwise would be worse than none - it would license
the belief that the rule is being watched.

## Labelling schema

Unchanged from what `scripts/precision.py` already reads, plus two fields:

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
      capability: sql      # sql | shell | exec | http | handoff   <- what the sink DOES
      verdict: flag        # `flag` counts toward recall; anything else is a note
      mitigation: none     # the repo's own defences on this path, or `none`
      code: "cur.execute(sql)"   # the exact sink text at the pinned ref
```

**A label names a capability, never a rule id.** This is the fix for the
vocabulary leak disclosed below, and validating rule ids was not enough - a
check confirmed it. `PI-EXEC` and `PI-FRAMEWORK-EXEC` share a sink category;
they differ in the shape of the **LLM call upstream**, which is not visible
anywhere near the sink line. Asking a labeller which one applies asks them to
open a rule file. Asking what the sink does asks them to read the line in front
of them:

| The sink | capability |
|---|---|
| a query is executed | `sql` |
| a shell command runs | `shell` |
| code runs - in-process, in an interpreter, or in a sandbox | `exec` |
| an outbound request is made to a URL | `http` |
| control passes to another agent | `handoff` |

`scripts/precision.py` maps rule ids onto these when scoring, so the engine's
taxonomy stays the engine's business. It also removed a measurement artifact: a
finding that traced the right path to the right line used to score as a miss
**and** a false positive if it arrived under the sibling rule id.

**The neutrality of that change is asserted at n=6, not proven.** Re-measuring
after it gave the identical 0/6, which is consistent with "no artifact was
present" and equally consistent with "an artifact was removed and a real miss
appeared, netting to zero". At six paths those cannot be distinguished, and it
does not matter for the published number because both readings leave it at
0/6. **Owed work:** re-run the comparison once held-out is substantially
larger, to confirm the capability mapping still does not flatter. Cheap, and
the only way the claim stops resting on a small sample.

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

## What counts as a path (decided before measuring, applied uniformly)

The first labelling pass produced 15 candidates. Six became labels. The three
rules below are what cut the other nine, and they are written here because a
curation rule applied case by case is indistinguishable from choosing the
answer.

1. **The wiring must be in this repo.** Untrusted text must reach the
   dangerous capability through code in the repo being scanned. A framework
   that merely *ships* a dangerous tool for a user to register does not
   qualify: `HttpPlugin.get(url)` is a plugin doing exactly its job, and
   reporting it would be a false positive against the framework, not a
   finding. The wiring lives in the adopter's repo, which is what Palisade
   scans there.
   This is the same standard that rejected Haystack's `LinkContentFetcher`
   during the pass, so applying it to Semantic Kernel's plugins and
   pydantic-ai's `web_fetch` tool is consistency, not convenience. It removed
   the largest single group of candidates.
2. **One label per mechanism, not per sibling.** Four near-identical methods
   of one class (`get`/`post`/`put`/`delete`) are one mechanism at four sites.
   Labelling all four makes `n` look bigger while making the estimate worse:
   the engine either handles the shape or it does not, so the four move
   together and one behaviour swings the number by 4/n.
3. **The sink is the earliest line at which the capability is exercised** on
   model-derived data. Where a flow loads an attacker-named module and then
   calls into it, the label goes on the load.

   *Disclosed:* this rule tends to pick the more recognisable of two adjacent
   lines, so it is not neutral with respect to the score. It was fixed before
   any measurement and applies to every future label, including ones where it
   costs. The alternative - choosing per label - is worse, because then the
   coordinate is chosen after the fact.

## Disclosure: what the labelling pass learned about the engine

The labelling itself was delegated to agents given the ground-truth criteria
and no knowledge of Palisade, which is why no candidate came back with a
diagnosis attached. But assigning each label a `rule:` id required knowing the
rule taxonomy, and in doing so this session read the rules' **sink
vocabularies**, not just their titles.

That is a partial leak and is recorded rather than glossed: generic knowledge
of which sink names are modelled is now held alongside six held-out labels, so
the *sink-vocabulary* dimension of these six is no longer strictly blind. The
taint-shape dimension is.

The first fix was to validate `rule:` ids against the shipped rules, on the
theory that a labeller needs the id to be valid and nothing more. **That was
not enough, and checking it is what showed so.** `PI-EXEC` and
`PI-FRAMEWORK-EXEC` both end in code execution; what separates them is the shape
of the LLM call upstream. A labeller staring at `session.run(code)` cannot tell
which applies without reading the rule definitions - so the leak would have
reopened on every label in every future batch.

Labels therefore name a **capability**, not a rule (see the schema above), and
`scripts/precision.py` maps rule ids onto capabilities at scoring time. Four
tests hold this in place, the load-bearing one asserting that the two exec
siblings share a single capability: the moment they differ, the question
"which one?" reaches a labeller again.

## Targets, and the first pass against them

| | Target | After pass 1 |
|---|---|---|
| Labelled paths | ~40 | 16 |
| Repos carrying labels | ~20 | 12 |
| Held-out paths | >= 15, across >= 6 repos | **6, across 4 repos** |

The target was not met, and was not padded to meet it. Of the 12 held-out
repos, 8 produced nothing: several are thin API clients or a vector store with
no text-generation call anywhere, and two agent frameworks dispatch only into
tools their adopter supplies.

**Batch 2 assigned 2026-09-30:** 24 further repos, 20 held-out / 4 train, seed
`20261001`, frozen and pushed before any of them was opened. Weighted harder
than batch 1 because train needs nothing and the estimate needs everything. At
batch 1's observed yield (~0.5 paths per repo) this should carry held-out into
the high teens; if it does not, the number is whatever it is and a third batch
follows.

Six paths is a weak estimate and every report of it must say so. Two ways to
grow it honestly:

- **Add repos**, assigned by the same recorded seeded shuffle before anyone
  reads them. Growing the corpus is always legitimate.
- **Retire train paths** as gaps close, which frees nothing - retiring moves
  the other way. There is no honest route from 6 to 15 that runs through the
  repos already assigned.

Relabelling an assigned repo, or loosening rule 1 above after seeing the
number, is the one-way door walked backwards.

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
