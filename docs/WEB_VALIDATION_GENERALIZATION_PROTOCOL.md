# Transparent Web-Validation Generalization Protocol

Status: preregistered; development corpus open; reserved corpus sealed
Protocol date: 2026-07-29
BELIEF starting commit:
`a5e9fdac71e96b39fffdd543e8c1e8135fc4f01e`

This protocol defines a new benchmark-independent development corpus after
the failed SusVibes semantic-development gate and the ineligible PatchEval
static preflight. It does not authorize opening the reserved SusVibes cohort,
running third-party code, or claiming an official `SecPass` result.

## Comparator boundary

The current external targets are methodologically different:

- the Agent Security League reports Cursor with Claude Fable 5 at `72.6%`
  `FuncPass` and `29.0%` fair `SecPass` on its 200-task evaluation;
- Aikido reports Kimi K3 at `23/26` known-CVE rediscoveries through a private,
  specialized multi-agent harness using pooled `pass@3`.

The first is an end-to-end patch score. The second is a private known-CVE
rediscovery result. Neither is comparable to the static, synthetic, or local
oracle metrics in this protocol.

Sources:

- <https://www.endorlabs.com/research/ai-code-security-benchmark>
- <https://www.endorlabs.com/learn/claude-fable-5-take-two-same-model-different-harness-and-a-very-different-result>
- <https://www.aikido.dev/blog/benchmarking-ai-models-known-cves>

## Corpus design

The frozen generator creates 48 cases from 12 complete application-template
families. Every family contains four variants:

1. vulnerable;
2. protected;
3. ambiguous;
4. false-positive trap.

The family matrix is balanced across:

| Dimension | Values |
|---|---|
| Framework | Flask, FastAPI |
| Vertical | path traversal, IDOR/BOLA |
| Route style | synchronous, asynchronous |
| Indirection | direct, helper, decorator, dependency |
| Resource representation | dictionary, model |
| Guard behavior | before sink, after sink, wrong resource |
| Authorization | authentication only, owner only, tenant only, owner and tenant |
| Path handling | unchecked join, used sanitizer result, ignored sanitizer result |

Source is synthetic and first-party. No external project, benchmark patch,
CVE, project name, or hidden test contributes to generation.

## Frozen family split

The split identifier is `sha256_stratified_template_family_v1`.

1. Group families by framework and vulnerability vertical.
2. Sort the three families in each stratum by stable family ID.
3. Hash the frozen seed, framework, and vertical.
4. Select exactly one family per stratum as reserved from the hash-derived
   index.
5. Assign the other two families to development.
6. Keep all four variants of a family in the same cohort.

The resulting partition is:

- development: 8 families, 32 cases;
- reserved: 4 families, 16 cases.

Outcomes, static findings, and runtime results are not allocation inputs.
The committed preregistration records all case IDs and aggregate digests, but
commits neither reserved source nor reserved outcomes.

## Frozen development gates

| Measurement | Gate |
|---|---:|
| Static precision | at least 70% |
| Static recall | at least 70% |
| Executable-plan coverage | at least 75% |
| Functional-baseline evaluability | at least 90% |
| Oracle evaluability | at least 85% |
| Abstention rate | at most 25% |
| Evidence-gap resolution | at least 70% |
| Protected regression rate | 0% |
| Functional regression rate | 0% |
| Worker timeout or crash rate | 0% |
| Repeated semantic-digest stability | 100% |
| Windows/Linux outcome agreement | at least 95% |

These values were fixed before running BELIEF over the development corpus.
They may not be lowered after observing results.

## Permitted development inputs

- development source and ground truth;
- development static findings;
- development validation plans and results;
- aggregate development metrics;
- independently created metamorphic mutations.

## Forbidden inputs

- reserved source or ground truth;
- reserved static findings, plans, results, traces, or per-case metrics;
- any SusVibes reserved artifact;
- official hidden functional or security tests;
- golden patches, CVE labels, or upstream project identities;
- a successful reserved result used to tune production rules.

## Current checkpoint

This checkpoint implements only:

- the deterministic generator;
- exact create-only preregistration;
- the public 32-case development source corpus;
- regeneration and drift verification;
- path-safety, syntax, balance, coverage, and sealing tests.

It does not execute the corpus or measure any gate. The next increment must
freeze a static-analysis/plan-generation runner before inspecting aggregate
development results. Runtime worker integration must remain bound to a closed
benchmark-only registry and must not expand MCP to arbitrary paths, modules,
or callables.

Reserved generation and execution require a later, separate freeze
attestation. If development fails any gate, the negative result is published
and the reserved cohort remains sealed.
