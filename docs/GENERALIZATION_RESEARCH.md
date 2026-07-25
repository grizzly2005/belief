# Generalization research for BELIEF

Research snapshot: 2026-07-25

This note records the design evidence used before changing BELIEF's reviewer.
It is deliberately separate from benchmark results and from the reserved
SusVibes cohort. No reserved task, patch, label, test, or result was inspected
to produce this document.

## Decision in one sentence

Keep BELIEF as a deterministic, benchmark-independent reviewer; add bounded
function summaries, explicit flow states, a compact evidence graph, and
semantic before/after comparison; retain CodeQL and Joern as optional passive
evidence providers; use dynamic security and functional tests only in an
isolated evaluator.

## Benchmark evidence

### SusVibes

SusVibes evaluates whether an agent can repair security vulnerabilities while
preserving functionality. Its central result is that functional success is
much higher than security success: a patch can pass ordinary tests and still
leave the vulnerability exploitable. The original arXiv release described 200
tasks from 108 projects and 77 CWEs. The current public repository and later
paper version contain 186 tasks, so every BELIEF result must pin the exact
dataset, commit, task count, and digest instead of referring to "SusVibes" as
if it were immutable.

Useful lessons:

- `FuncPass` and `SecPass` answer different questions and must both be shown.
- A static warning is neither a generated repair nor a `SecPass`.
- Security hints alone did not close the security gap in the original study.
- Dataset and harness versions are part of the result, not incidental details.
- Golden patches, security tests, CWE/CVE labels, and task metadata belong to
  the evaluator and must never reach the reviewer.

### Endor Labs Agent Security League

The league reproduces and extends SusVibes with pinned agent/harness versions,
containerized task execution, workspace hardening, cheating checks, and
separate functional and security scores. The public table is live and can
change. On the 2026-07-25 snapshot, Cursor with Claude Fable 5 reported
72.6% `FuncPass` and 29.0% `SecPass`; Claude Code with the same model reported
59.8% and 19.0%. This is strong evidence that the harness, context management,
tool loop, and patch placement materially affect results even when the model is
held constant.

Useful lessons:

- Reproduce first, then extend; never compare against a differently filtered
  denominator.
- Pin the agent, model, harness, image, budget, timeout, and prompt.
- Sanitize Git history and the workspace because benchmark patches can leak
  through local history, caches, or network retrieval.
- Record infeasible or infrastructure-failed tasks explicitly.
- Report one-shot success (`pass@1`) unless a different attempt policy was
  preregistered.
- A BELIEF feedback experiment must compare the same agent/harness with and
  without BELIEF. Comparing BELIEF static recall to league `SecPass` is invalid.

The gap between the two Fable 5 harnesses also supports a practical direction:
BELIEF should return concise, localized, causal evidence that an agent can act
on, rather than a long undifferentiated list of possible weaknesses.

### AI Agents That Matter

This work argues that agent evaluation must account for cost, repeated
attempts, downstream application requirements, and reproducibility. A higher
headline accuracy obtained with more calls or a larger budget is not a
like-for-like improvement.

BELIEF consequence:

- report token/cost budgets and attempt counts;
- distinguish reviewer quality from the end-to-end repair agent;
- use paired same-task comparisons;
- preserve failed and expensive runs;
- do not use repeated sampling to silently turn `pass@1` into a best-of-N
  number.

### SWE-rebench

SWE-rebench builds fresh, executable software-engineering tasks from recent
repositories and exact environments. Its continuous temporal slices and
automated curation are a useful answer to contamination and benchmark
staleness, although large-scale curation introduces its own validation
trade-offs.

BELIEF consequence:

- reserve a truly unseen temporal or project slice for later confirmation;
- bind results to source and environment digests;
- prefer exact executable environments over textual similarity judgments;
- publish task-selection and exclusion rules before seeing outcomes.

## Static-analysis architecture evidence

### CodeQL data flow

CodeQL separates local flow from global flow. Local flow is cheaper and more
precise; global flow uses a configuration containing sources, sinks, barriers,
and additional steps and is intentionally more expensive. Taint tracking adds
non-value-preserving transformations. Path queries expose an auditable route
from source to sink instead of only a terminal warning.

Flow states make partial sanitization explicit. A value may be safe for one
property and unsafe for another: for example, URL-scheme validation does not
also prove host authorization. Barrier guards model predicates that block a
specific state only on the guarded branch.

Models-as-data encode sources, sinks, summaries, barriers, and barrier guards
for libraries without hard-wiring every library into the analysis engine.

BELIEF will borrow these concepts, not CodeQL's implementation:

- local-first and bounded global flow;
- explicit flow-state lattices;
- value-, resource-, and context-specific barriers;
- barrier guards attached to the correct control-flow branch;
- deterministic source-to-sink evidence paths;
- external summaries as data where their provenance and license permit it.

The existing CodeQL SARIF bridge remains passive and optional. A later
proof-of-concept may import path evidence from a pinned offline CodeQL run, but
BELIEF must still work when the CLI is absent. The CodeQL CLI is available for
research and analysis of public code under GitHub's terms; its distribution
and private-code use are not equivalent to a permissively licensed dependency.

### Joern and the Code Property Graph

The Code Property Graph (CPG) combines syntax, control flow, call relations,
dominance, and data dependence in a directed, attributed multigraph. This is a
good conceptual match for an explanation object that must retain both
data-flow and control-flow evidence.

Joern's data-flow semantics also illustrate a precision hazard: overly broad
default semantics for external calls propagate taint between arguments and
returns, while explicit receiver/argument/return summaries reduce false
positives.

BELIEF will therefore use a much smaller internal evidence graph rather than
adopt Joern as its core. Joern remains an Apache-2.0, JVM/Scala-based optional
provider whose output may be normalized by the existing bridge. Replacing the
Python-native reviewer with Joern would add substantial runtime and packaging
cost before proving a benchmark gain.

### Semgrep Community Edition and Pro

Semgrep Community Edition is a fast deterministic syntax/pattern engine and is
useful for local structural evidence. Its open engine is LGPL-2.1, while the
maintained rule registry has separate Semgrep Rules License terms that must not
be conflated with the engine license. Community Edition is primarily
single-file; cross-function and cross-file capabilities are offered by the
proprietary Pro engine.

BELIEF consequence:

- retain passive import and optional local CE use;
- do not make proprietary Pro a required dependency;
- do not copy rules without checking their individual license;
- use CE as supporting evidence, not as the sole semantic verdict.

## Repair and executable-validation evidence

### Counterexample-guided repair with MaxSAT

The AAAI work combines MaxSAT-based fault localization, LLM-generated repair
sketches, and test counterexamples. Its evaluated domain is student programs,
so the reported repair rate cannot be transferred to real security patches.
The reusable idea is narrower: propose the smallest repair consistent with
current evidence, execute tests, and feed each counterexample back into the
next constrained attempt.

BELIEF consequence:

- reviewer findings should identify a root cause and violated state, not
  prescribe an exact benchmark patch;
- an agent loop may consume a bounded sequence of BELIEF evidence and dynamic
  counterexamples;
- minimal-diff preference is useful but never substitutes for security tests.

### PatchEval

PatchEval evaluates vulnerability repairs with both a security proof-of-concept
and functional tests in a sandbox. It covers multiple languages and offers
location-oracle and end-to-end modes. The authors show why patch similarity and
LLM judges are weaker than executable validation.

BELIEF consequence:

- the eventual end-to-end claim requires executable functional and adversarial
  tests;
- dynamic execution belongs to an isolated, resource-limited evaluator;
- pass/fail should include both vulnerability removal and regression absence;
- PatchEval is a possible future external validation corpus, not a dependency
  of the deterministic reviewer;
- repository and artifact licenses must be verified for the exact version
  before any redistribution or vendoring.

### NIST SARD and Juliet

SARD contains synthetic, academic, and production-derived test cases and
explicitly records known errors and revisions. Juliet pairs "bad" and "good"
variants and repeats weaknesses across many control-flow, data-flow,
interprocedural, and multi-file shapes.

BELIEF will borrow Juliet's evaluation principles, not use it as the main
Python benchmark:

- hold the semantic weakness constant while changing syntax and flow shape;
- pair positive and negative variants;
- include wrong-value, wrong-resource, wrong-order, bypass-branch, and
  interprocedural counterexamples;
- preserve known dataset limitations and version metadata.

The C/C++ and Java Juliet suites do not represent BELIEF's primary Python
target distribution. Passing synthetic variants cannot establish an
end-to-end SusVibes win.

## Options matrix

| Approach | Expected gain | Cost | Risk | License / terms | Decision |
|---|---|---:|---|---|---|
| BELIEF deterministic core | High precision and reproducible reviewer behavior; direct control over diagnostics and limits | Medium engineering | Incomplete language/library models; accidental rule growth | BELIEF MIT; only compatible incorporated data | **Keep as core** |
| Optional CodeQL bridge | High-quality global paths and library models for supported families | Medium/High runtime and setup | Terms, availability, DB build cost, version drift, false confidence when absent | GitHub CodeQL CLI terms; public-research use differs from redistribution/private use | **Passive, pinned POC only after core ablation** |
| Joern / CPG | Unified syntax/control/data evidence; multi-language potential | High JVM/Scala and semantic-model cost | Heavy dependency; overly broad external-call flow; duplicate core | Apache-2.0 for Joern; check bundled components | **Borrow graph concepts; keep optional bridge** |
| Semgrep CE | Fast structural matches and broad syntax coverage | Low/Medium | Mostly per-file; rule quality and licensing vary | Engine LGPL-2.1; registry rules have separate terms | **Optional supporting evidence** |
| Semgrep Pro | Interfile/cross-function analysis with low integration effort | Monetary/proprietary dependency | Non-reproducible availability; vendor/version coupling | Proprietary commercial terms | **Not mandatory; exclude from deterministic baseline** |
| LLM analysis inside verdict | Potential coverage on unseen APIs and intent | High variable cost | Nondeterminism, leakage, prompt injection, memorization, irreproducible verdict | Provider/model-specific | **Do not put in deterministic verdict yet** |
| Dynamic functional/security tests | Direct evidence of preserved behavior and vulnerability removal | High environment and sandbox cost | Unsafe execution, flaky tests, infeasible images, oracle leakage | Dataset/project specific | **Required in isolated end-to-end evaluator** |
| Fuzzing / property testing | Finds bypasses not encoded in fixed tests; strong counterexamples | Medium/High and potentially unbounded | Resource blow-up, unstable coverage, target execution risk | Tool/corpus specific | **Bounded, opt-in, post-static evidence** |
| Counterexample-guided repair | Turns failed security/functional tests into targeted next attempts | Medium/High agent-loop work | Overfitting to tests; repeated-attempt budget inflation | Implementation/model specific | **Future bounded agent loop, preregister attempts** |

## Selected architecture

```text
candidate source
      |
      v
deterministic syntax and scope selection
      |
      v
bounded function summaries ---- optional passive evidence imports
      |                          (CodeQL SARIF / Joern / Semgrep)
      v
flow states + control/resource identity
      |
      v
small deterministic EvidenceGraph
      |
      v
semantic vulnerable/secure comparison
      |
      +--> actionable finding with causal path
      +--> explicit AnalysisGap with a limit/reason
      |
      v
isolated repair agent (later experiment)
      |
      v
functional tests AND security tests
```

The core output must be reproducible from source bytes and configuration. It
must expose when a call, branch, alias, state transition, or resource identity
could not be modeled. Resource limits are part of the result; reaching one
produces an explicit gap, never an implicit clean verdict.

The first implementation cycle is limited to the three most transversal
failure clusters found on the development cohort. A semantic primitive enters
production only when it:

1. explains cases from multiple projects and weakness families or a clearly
   reusable family abstraction;
2. has at least three positive and three negative synthetic/metamorphic tests;
3. does not contain benchmark IDs, project names, CVEs, exact reference-patch
   fragments, or result paths;
4. improves a preregistered ablation without breaking protected mutations.

## What would count as beating Fable 5 or Kimi

A BELIEF static paired-discrimination percentage above 29% does **not** count.
The claim requires, at minimum:

- the same public benchmark version and same task denominator;
- a pinned model and agent harness;
- a clean, sanitized workspace with no benchmark-answer access;
- the same `pass@1`, budget, timeout, and task-exclusion policy;
- functional and security tests executed in the official or faithfully
  reproduced sandbox;
- a no-BELIEF control and a BELIEF-feedback arm;
- immutable per-task artifacts, failures, costs, and provenance;
- at least two deterministic BELIEF analysis runs at the frozen reviewer
  revision before the reserved static cohort is inspected.

Until that experiment exists, comparisons to the live Endor table are targets,
not wins.

## References

All links were accessed on 2026-07-25.

- SusVibes paper: https://arxiv.org/abs/2512.03262
- SusVibes official repository: https://github.com/LeiLiLab/susvibes
- SusVibes official leaderboard: https://leililab.github.io/susvibes-leaderboard/
- Endor Agent Security League: https://www.endorlabs.com/research/ai-code-security-benchmark
- Endor methodology whitepaper: https://www.endorlabs.com/learn/agent-security-league-evaluating-the-security-of-ai-coded-software
- Fable 5 harness comparison: https://www.endorlabs.com/learn/claude-fable-5-take-two-same-model-different-harness-and-a-very-different-result
- Endor benchmark-cheating analysis: https://www.endorlabs.com/learn/recall-not-reasoning-how-ai-coding-agents-cheat-security-benchmarks
- AI Agents That Matter: https://arxiv.org/abs/2407.01502
- SWE-rebench: https://arxiv.org/abs/2505.20411
- CodeQL Python data flow: https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/
- CodeQL flow states: https://codeql.github.com/docs/codeql-language-guides/using-flow-labels-for-precise-data-flow-analysis/
- CodeQL Python models-as-data: https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-python/
- CodeQL path queries: https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/
- CodeQL CLI terms and availability: https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli
- CodeQL pack pinning: https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/codeql-query-packs
- Code Property Graph specification: https://cpg.joern.io/
- Joern CPG documentation: https://docs.joern.io/code-property-graph/
- Joern data-flow semantics: https://docs.joern.io/dataflow-semantics/
- Joern repository: https://github.com/joernio/joern
- Semgrep Community Edition: https://semgrep.dev/products/community-edition/
- Semgrep open-source licensing update: https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss
- Semgrep glossary and engine boundaries: https://semgrep.dev/docs/writing-rules/glossary
- Semgrep Pro engine: https://semgrep.dev/products/pro-engine/
- Semgrep taint concepts: https://semgrep.dev/blog/2022/demystifying-taint-mode/
- Counterexample-guided repair with MaxSAT: https://ojs.aaai.org/index.php/AAAI/article/view/32046
- PatchEval paper: https://arxiv.org/abs/2511.11019
- PatchEval repository: https://github.com/bytedance/PatchEval
- PatchEval project page: https://patcheval.github.io/
- NIST SARD: https://samate.nist.gov/SARD/
- SARD manual: https://www.nist.gov/itl/csd/secure-systems-and-applications/software-assurance-reference-dataset-sard-manual
- Juliet 1.1 paper: https://www.nist.gov/publications/juliet-11-cc-and-java-test-suite
- Juliet 1.3 suite: https://samate.nist.gov/SARD/test-suites/112
- SARD documentation: https://samate.nist.gov/SARD/documentation
