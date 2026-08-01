# Duck-oriented C path-objective pilot

Status: research-only, synthetic, non-executing.

This pilot defines a narrow boundary between a BELIEF `ValidationPlan` and a
manually produced C reachability artifact. It does **not** embed Duck, an LLM,
a compiler, a symbolic executor, or arbitrary project code in BELIEF.

## Scientific scope

The public research around *Large Language Model Powered Symbolic Execution*
describes code-based symbolic execution, path decomposition, and generated
path-constraint programs. The publication and archived artifact are useful
architectural references:

- [Gregory Duck's publication page](https://www.comp.nus.edu.sg/~gregory/)
- [Large Language Model Powered Symbolic Execution](https://doi.org/10.1145/3763163)
- [archived research artifact](https://zenodo.org/records/17215629)

BELIEF has not verified a small, stable public Duck input/output wire protocol.
Consequently, this branch is described as **Duck-oriented**, not Duck-compatible.
The manual C fragment and the BELIEF path-artifact JSON are BELIEF contracts;
they are not represented as formats accepted or emitted by Duck.

## Closed pipeline

```text
ValidationPlan with explicit C reachability hints
  -> ExplorationObjective
  -> manual C function-scope fragment
  -> external/manual research step outside BELIEF
  -> strict PathArtifact JSON import
  -> supported | refuted | inconclusive
```

Only plan projection, fragment rendering, artifact import, and assessment are
implemented. The external/manual step is deliberately absent. BELIEF does not locate a tool,
invoke a command, compile the fragment, load a module, accept a callable, or
open an analyzed source tree in this pilot.

## `ExplorationObjective`

The runtime contract and public schema are:

- `belief.exploration_objective.v1`;
- [`schemas/belief.exploration-objective.v1.schema.json`](../schemas/belief.exploration-objective.v1.schema.json).

Projection from `ValidationPlan` is fail-closed. The plan must already contain
`belief.validation_reachability.v1` hints with all of the following exact
fields:

```json
{
  "language": "c",
  "function_context": {"name": "authorize_request"},
  "sink": {
    "file": "src/authorization.c",
    "line": 18,
    "symbol": "sensitive_operation"
  },
  "candidate_constraint": {
    "expression": "requested_id != owned_id",
    "logic": "c_boolean_expression_v1",
    "origin": "human_reviewed_candidate"
  }
}
```

The compiler never infers a constraint from a plan objective, evidence-gap
prose, a code comment, or an LLM response. Existing `ValidationPlan` identity
validation runs before projection, and the resulting objective ID is derived
deterministically from its complete semantic content.

The constraint grammar is intentionally small and side-effect-free:

- ASCII C identifiers and decimal/hexadecimal integers;
- parentheses and unary `!`;
- `==`, `!=`, `<`, `<=`, `>`, and `>=`;
- `&&` and `||`;
- at most 512 characters.

Calls, assignments, member/pointer access, strings, comments, indexing,
arithmetic, preprocessor syntax, statement separators, and braces are rejected.
This validates a transport subset; it does not prove that a candidate
constraint is semantically correct for a real C program.

## Manual C exporter

`export_c_reachability_probe()` is a pure renderer. It returns a bounded
function-scope fragment and its SHA-256 digest:

```c
if (requested_id != owned_id) {
    BELIEF_REACHABILITY_TARGET();
}
```

The returned contract explicitly records `compiled=false` and
`executed=false`. It does not write a `.c` file and does not claim that the
fragment is a complete translation unit.

## Path artifact import

The importer accepts only bounded, duplicate-free, finite, strict UTF-8 JSON
matching `belief.path_artifact.v1` and
[`schemas/belief.path-artifact.v1.schema.json`](../schemas/belief.path-artifact.v1.schema.json).
It binds the artifact to one exact deterministic objective ID. A plausible
path must begin at the named function entry and end at the exact target file,
line, and symbol. Paths are capped at 256 steps.

Interpretation is deliberately conservative:

| Artifact outcome | BELIEF interpretation | Meaning |
| --- | --- | --- |
| `plausible_path_artifact` | `supported` | the imported artifact supports the candidate reachability claim |
| `no_plausible_path` | `refuted` | the imported artifact refutes that candidate claim under its stated model |
| `inconclusive` | `inconclusive` | evidence remains unresolved; BELIEF abstains |

Every assessment emits `confirms_vulnerability=false`. Even `supported` is not
an exploit, a vulnerability confirmation, or authorization to test a target.

## Synthetic pilot benchmark

The closed corpus contains exactly three synthetic contract examples: one for
each artifact outcome and one for each interpretation. It contains no real
project source and executes no external analyzer.

Run it with a new output path:

```powershell
python scripts/benchmark_exploration_objective.py `
  --output out/exploration-objective-pilot.json
```

The report is create-only and deterministic. Its expected contract-level
result is 3/3 label matches with one preserved abstention (1/3). This is a
self-consistency check for serialization, binding, and interpretation—not an
accuracy result for Duck, an LLM, BELIEF vulnerability discovery, SecPass, or
any leaderboard.

## Deferred experiment

A later, separately preregistered experiment may compare `LLM only`, `BELIEF
only`, `BELIEF + LLM`, `BELIEF + reachability tool`, and the complete hybrid.
That work needs a pinned external tool revision, an exact adapter protocol,
authorized source inputs, blind labels, cost/time capture, repeated trials,
and an independently evaluated holdout. None of those five experimental arms
is implemented or claimed here.

## Verification

```powershell
python -m pytest -q tests/test_exploration_objective.py `
  tests/test_exploration_pilot_benchmark.py
python -m ruff check belief/exploration `
  tests/test_exploration_objective.py `
  tests/test_exploration_pilot_benchmark.py `
  scripts/benchmark_exploration_objective.py
```
