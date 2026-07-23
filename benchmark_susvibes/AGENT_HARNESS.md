# BELIEF-assisted SusVibes agent harness

This harness is the path from BELIEF's offline static measurements to a real
SusVibes `FuncPass` / `SecPass` experiment. It runs a coding agent inside the
official task image, reviews the candidate diff at the agent's Stop boundary,
and can return one bounded, oracle-free security repair request in the same
attempt.

It does **not** claim a `SecPass` score until the emitted predictions have been
evaluated by SusVibes' functional and hidden security tests.

## Why the harness is part of the result

The public Agent Security League reports that the same Fable 5 model changes
from 19% `SecPass` under Claude Code to 29% under Cursor. The benchmark is
therefore a measurement of a model-and-harness combination, not model weights
alone:

- leaderboard: <https://www.endorlabs.com/research/ai-code-security-benchmark>
- harness comparison:
  <https://www.endorlabs.com/learn/claude-fable-5-take-two-same-model-different-harness-and-a-very-different-result>

BELIEF's experiment is consequently named
`belief-claude-hook/<exact-model-id>` in prediction records.

## Trust boundaries

Only these dataset fields cross into the agent harness:

- `instance_id`;
- `image_name`;
- `problem_statement`.

The agent and BELIEF reviewer do not receive `security_patch`, `test_patch`,
`golden_patch`, CWE labels, CVE labels, or hidden-test outcomes.

Before the agent starts, the extracted task copy is converted to a fresh,
single-commit Git repository. All root and nested `.git` metadata are removed,
so the upstream fix cannot be recovered from local Git objects. The canonical
SusVibes anti-cheating prompt is retained. Claude web tools are not enabled,
and a `PreToolUse` hook denies obvious web and Git-history recovery commands.
The transcript is also marked when it contains a policy indicator.

The command hook is defense in depth, not a sandbox for arbitrary hostile
code. The history-free workspace is the primary local anti-cheating boundary.

## Bounded feedback loop

At Claude's `Stop` event:

1. BELIEF computes the current candidate diff against the fresh baseline.
2. It analyzes only changed Python production code.
3. It compares candidate observations with the clean baseline.
4. If an actionable regression or residual security risk remains, the Stop
   hook returns concise feedback and blocks Stop once by default.
5. Claude repairs the same candidate in the same session.
6. A repeated identical patch or the configured block limit ends the loop.

The default is one repair continuation. `--max-stop-blocks` accepts `0` to
`3`; a larger value changes the harness budget and must be recorded when
comparing scores.

Hook state and full review reports live outside the candidate workspace and
are copied into the task result artifacts after the run.

## Safe dry run

Dry run is the default. It reads the pinned dataset, selects one task, and
prints a provenance plan containing hashes rather than the problem text. It
does not create the results directory, start Docker, pull an image, or call a
model API.

```powershell
python scripts/run_susvibes_belief_claude.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --results-dir F:\belief-rd\agent-runs\trial-001 `
  --model <exact-anthropic-model-id> `
  --plan-output F:\belief-rd\results\agent-plan-001.json
```

The plan output is create-only: an existing file is rejected rather than
overwritten.

For a score-bearing experiment, first freeze the public corpus into
deterministic smoke, canary, and full cohorts:

```powershell
python scripts/prepare_susvibes_experiment.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --output F:\belief-rd\results\susvibes-experiment-001.json `
  --smoke-size 3 `
  --canary-size 24 `
  --batch-size 12
```

The create-only evaluator manifest is ordered by a dataset-hash-seeded,
primary-CWE round robin. It records coverage metadata for analysis, but the
runner verifies the manifest and dataset hashes and reads only the selected
instance IDs. Neither the CWE strata nor project metadata cross the agent
boundary.

Use the frozen selection even for the dry run:

```powershell
python scripts/run_susvibes_belief_claude.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --cohort smoke `
  --num-instances 3 `
  --results-dir F:\belief-rd\agent-runs\smoke-001 `
  --model <exact-anthropic-model-id> `
  --plan-output F:\belief-rd\results\smoke-plan-001.json
```

The dry-run contract was exercised on 2026-07-23 against SusVibes commit
`66d305a7a8541f4faa245171b359a6b0d141941e`. The plan retained the v1.0 dataset
hash, exposed exactly the three allowed fields, recorded a one-block feedback
budget, and left the requested results directory absent. No Docker or model
execution was performed.

## Read-only execution preflight

Before execution, create a report bound to the exact checkout, dataset,
experiment manifest, cohort, results directory, model, Claude Code version,
and runner SHA-256:

```powershell
python scripts/preflight_susvibes_agent.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --cohort smoke `
  --results-dir F:\belief-rd\agent-runs\smoke-001 `
  --model <exact-anthropic-model-id> `
  --claude-version 2.1.83 `
  --acknowledge-agent-network `
  --output F:\belief-rd\results\smoke-preflight-001.json
```

The preflight never starts Docker, pulls an image, calls a model, or reports a
credential value. It checks an already-running Docker daemon read-only and
records only the names of available credential variables. It exits `1` and
still creates an evidence report when readiness checks fail; that report is
not a benchmark result. Reports are create-only and self-digest-checked. A
runner accepts a ready report for 15 minutes and rechecks the dataset, Git
state, runner hash, output directory, free space, credentials, and Docker
availability before execution.

## Explicit execution

Real execution requires the verified manifest/cohort, a matching ready
preflight report, both explicit flags (`--execute` and
`--allow-agent-network`), an exact model identifier, an API credential in
`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, and an already-running Docker
daemon:

```powershell
python scripts/run_susvibes_belief_claude.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --cohort smoke `
  --preflight-report F:\belief-rd\results\smoke-preflight-001.json `
  --results-dir F:\belief-rd\agent-runs\smoke-001 `
  --model <exact-anthropic-model-id> `
  --claude-version 2.1.83 `
  --max-stop-blocks 1 `
  --num-instances 3 `
  --execute `
  --allow-agent-network
```

The runner:

- never starts or reconfigures Docker;
- rejects unmanifested execution and stale, modified, or mismatched preflight
  evidence;
- refuses a non-empty results directory;
- executes tasks sequentially;
- injects credentials through container stdin into a mode-`0600` environment
  file rather than placing secrets in command arguments or logs;
- pins the Claude Code CLI version;
- preserves complete stdout, stderr, hook reports, patch hashes, and
  provenance;
- emits official three-field prediction JSONL.

Network acknowledgement is necessary because Docker may pull the task image,
the CLI pin uses npm, and the agent calls the configured model API.

## Official evaluation

Evaluate the produced `predictions.jsonl` with the pinned SusVibes checkout:

```powershell
Set-Location F:\belief-rd\susvibes-main

python -m susvibes.eval.core `
  --run_id belief-trial-001 `
  --predictions_path F:\belief-rd\agent-runs\trial-001\predictions.jsonl `
  --max_workers 1
```

Keep generation and evaluation run IDs, dataset hash, SusVibes commit, exact
model ID, Claude Code version, feedback budget, prediction file, and evaluator
summary together. Use at least two independent full runs before interpreting a
small score difference; the public methodology reports meaningful run-to-run
variance.

The 24-case canary deliberately maximizes breadth across CWE strata and
projects; it is an engineering signal, not a prevalence-weighted leaderboard
estimate. Only the complete pinned public cohort evaluated with official
`FuncPass` and `SecPass` tests is score-bearing.

## Comparability rules

A claim against the Agent Security League requires the same 200-task set,
anti-cheating policy, one attempt per task, and official `SecPass` semantics.
The public SusVibes v1.0 repository currently contains 186 tasks after removing
14 brittle cases, so a local v1.0 result must be labeled as such and must not be
presented as a direct 200-task leaderboard win.

Kimi K3's reported 23/26 result is also not directly comparable: it uses a
private, known-CVE, pass@3 benchmark with a specialized multi-agent harness:
<https://www.aikido.dev/blog/benchmarking-ai-models-known-cves>.
