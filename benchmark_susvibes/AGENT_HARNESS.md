# BELIEF-assisted SusVibes agent harness

This harness is the path from BELIEF's offline static measurements to a real
SusVibes `FuncPass` / `SecPass` experiment. It runs paired coding-agent arms
inside the official task image. The control keeps the anti-cheating policy but
has no `Stop` hook; the treatment reviews the candidate diff at `Stop` and can
return one bounded, oracle-free security repair request in the same attempt.

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

Prediction records distinguish
`claude-code-baseline/<exact-model-id>` from
`belief-claude-hook/<exact-model-id>`. They must be evaluated separately.

## Target model identity

Anthropic's official model overview identifies Claude Fable 5 as the pinned
Claude API model ID `claude-fable-5` and lists it as generally available.
Score-bearing Fable experiments use that full ID, not a moving alias:

- model overview:
  <https://platform.claude.com/docs/en/about-claude/models/overview>
- release notes:
  <https://platform.claude.com/docs/en/release-notes/overview>

The runner passes `--model claude-fable-5` explicitly, which takes precedence
over ambient Claude settings. It does not configure `--fallback-model`.
Structured output must identify the requested model before a completed batch
can be merged. Fable safety refusals and same-model API retry events are
retained as provenance rather than hidden. Published general availability
does not prove that a particular container credential has access, so the
offline preflight continues to mark live provider access as unverified.

Claude Code `2.1.170` is the first release that advertises Fable 5 access, so
the preflight rejects older pins. The frozen experiment uses `2.1.218`; its
official release, npm integrity, and shasum are recorded in
`claude_code_target_2026-07-23.json`. After installation, every task probes
`claude --version`; the merger rejects a requested/observed version mismatch.

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

BELIEF replaces the upstream persistent-container launch method without
modifying the pinned SusVibes checkout. Agent containers use Docker bridge
networking (model access remains possible), 4 CPUs, 8 GiB RAM with no extra
swap, a 512-process ceiling, all Linux capabilities dropped,
`no-new-privileges`, a bounded `/tmp`, and an init process. The only host mount
is the isolated task workspace. Host networking and the Docker socket are not
exposed.

The harness deliberately does not reuse a Claude subscription session from the
Windows host. Running the agent on the host would broaden its filesystem
authority beyond the isolated task workspace, while copying or mounting OAuth
state into Docker would move a user credential across the boundary. Real runs
therefore require an explicitly supplied container-scoped
`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`.

## Bounded feedback loop

At Claude's `Stop` event:

1. BELIEF computes the current candidate diff against the fresh baseline.
2. It analyzes only changed Python production code.
3. It compares candidate observations with the clean baseline.
4. If an actionable regression or residual security risk remains, the Stop
   hook returns concise feedback and blocks Stop once by default.
5. Claude repairs the same candidate in the same session.
6. A repeated identical patch or the configured block limit ends the loop.

The treatment default is one repair continuation. It requires
`--feedback-mode belief` and one to three `--max-stop-blocks`. A true control
requires `--feedback-mode none --max-stop-blocks 0`; in that mode the settings
contain only the common `PreToolUse` anti-cheating hook, so BELIEF never reviews
the patch or emits a `Stop` message. The preflight, plan, task result, run
summary, and merger all bind this distinction.

Hook state and full review reports live outside the candidate workspace, are
copied into the task result artifacts after the run, and are summarized into
validated review/block telemetry.

## Safe dry run

Dry run is the default. It reads the pinned dataset, selects one task, and
prints a provenance plan containing hashes rather than the problem text. It
does not create the results directory, start Docker, pull an image, or call a
model API.

```powershell
python scripts/run_susvibes_belief_claude.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --results-dir F:\belief-rd\agent-runs\trial-001 `
  --model claude-fable-5 `
  --feedback-mode belief `
  --max-stop-blocks 1 `
  --plan-output F:\belief-rd\results\agent-plan-001.json
```

The plan output is create-only: an existing file is rejected rather than
overwritten.

For a score-bearing experiment, first freeze the public corpus into
deterministic smoke, canary, holdout, and full cohorts:

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
boundary. The holdout is the exact complement of the 24-case engineering
canary and is frozen before any canary-driven harness tuning.

Before any paid smoke, create a paired preregistration. It binds a clean BELIEF
commit and runner hash, the exact three-task smoke slice, model and CLI version,
two distinct future result directories, and arms A=`none/0` and B=`belief/1`.
It records only the ordered task-ID digest, not task IDs or problem text:

```powershell
python scripts/prepare_susvibes_paired_smoke.py `
  --susvibes-root F:\belief-rd\susvibes-v1.0 `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --baseline-results-dir F:\belief-rd\agent-runs\smoke-a-baseline `
  --belief-results-dir F:\belief-rd\agent-runs\smoke-b-belief `
  --baseline-preflight-report F:\belief-rd\results\smoke-a-preflight.json `
  --belief-preflight-report F:\belief-rd\results\smoke-b-preflight.json `
  --model claude-fable-5 `
  --num-instances 3 `
  --output F:\belief-rd\results\paired-smoke-preregistration.json
```

This command requires both source checkouts to be clean, is create-only, and
does not start Docker, call a model, or execute benchmark tests.

Use the frozen selection even for the dry run:

```powershell
python scripts/run_susvibes_belief_claude.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --cohort smoke `
  --num-instances 3 `
  --results-dir F:\belief-rd\agent-runs\smoke-001 `
  --model claude-fable-5 `
  --feedback-mode belief `
  --max-stop-blocks 1 `
  --plan-output F:\belief-rd\results\smoke-plan-001.json
```

The dry-run contract was exercised on 2026-07-23 against SusVibes commit
`66d305a7a8541f4faa245171b359a6b0d141941e`. The plan retained the v1.0 dataset
hash, exposed exactly the three allowed fields, recorded a one-block feedback
budget, and left the requested results directory absent. No Docker or model
execution was performed.

## Read-only execution preflight

Before execution, create one report per arm. Each report is bound to the exact
checkout, dataset, experiment manifest, cohort, results directory, model,
Claude Code version, feedback mode, feedback budget, and runner SHA-256:

```powershell
python scripts/preflight_susvibes_agent.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --cohort smoke `
  --num-instances 3 `
  --results-dir F:\belief-rd\agent-runs\smoke-001 `
  --model claude-fable-5 `
  --claude-version 2.1.218 `
  --feedback-mode belief `
  --max-stop-blocks 1 `
  --acknowledge-agent-network `
  --acknowledge-scoped-credential `
  --output F:\belief-rd\results\smoke-preflight-001.json
```

For arm A, use its preregistered paths with
`--feedback-mode none --max-stop-blocks 0`. For arm B, use
`--feedback-mode belief --max-stop-blocks 1`. A report from one arm is rejected
by the other.

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
`--allow-agent-network`), an explicit scoped-credential confirmation, an exact
model identifier, an API credential in
`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, and an already-running Docker
daemon:

```powershell
python scripts/run_susvibes_belief_claude.py `
  --susvibes-root F:\belief-rd\susvibes-main `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --cohort smoke `
  --preflight-report F:\belief-rd\results\smoke-preflight-001.json `
  --results-dir F:\belief-rd\agent-runs\smoke-001 `
  --model claude-fable-5 `
  --claude-version 2.1.218 `
  --feedback-mode belief `
  --max-stop-blocks 1 `
  --num-instances 3 `
  --execute `
  --allow-agent-network `
  --confirm-scoped-agent-credential
```

Run each arm against its own matching report and result directory. Neither
command may reuse the other arm's output.

The runner:

- never starts or reconfigures Docker;
- rejects unmanifested execution and stale, modified, or mismatched preflight
  evidence;
- refuses a non-empty results directory;
- executes tasks sequentially;
- converts per-task timeouts and bounded runner failures into explicit,
  redacted empty-patch submissions, then continues the frozen denominator;
- injects credentials through container stdin into a mode-`0600` environment
  file rather than placing secrets in command arguments or logs;
- pins the Claude Code CLI version;
- pins the exact model through the CLI and configures no automatic fallback;
- restricts built-in tools, disables MCP servers, browser integration, skills,
  lower-scope settings, auto-memory, and session persistence;
- preserves complete stdout, stderr, hook reports and state, patch hashes,
  actual feedback-block counts, and provider-reported cost/token accounting;
- emits official three-field prediction JSONL.

Network acknowledgement is necessary because Docker may pull the task image,
the CLI pin uses npm, and the agent calls the configured model API.
The separate credential acknowledgement confirms that the supplied key/token
is benchmark-only, revocable, spend-limited, and not a copied host OAuth
session. The offline preflight cannot independently prove provider-side scope.

## Batch assembly

Long canary, holdout, and full runs should use small sequential result
directories. Each preflight is bound to the exact `--start-index`,
`--num-instances`, and task-ID digest used by its runner invocation. After all
batches complete, merge them in frozen cohort order:

```powershell
python scripts/merge_susvibes_predictions.py `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --dataset F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --cohort holdout `
  --run-dir F:\belief-rd\agent-runs\holdout-repeat-a-batch-001 `
  --run-dir F:\belief-rd\agent-runs\holdout-repeat-a-batch-002 `
  --output F:\belief-rd\results\holdout-repeat-a-predictions.jsonl `
  --provenance-output F:\belief-rd\results\holdout-repeat-a-merge.json
```

The merger rejects missing or duplicate tasks, mixed models, feedback modes,
or feedback budgets, dry-run plans, mismatched preflight slices, unverified
observed model identity, configured fallbacks, malformed stream output,
modified task results, unexpected agent-visible fields, and
plan/result/prediction hash inconsistencies. `--allow-partial` exists only for
explicitly incomplete diagnostics. Refusals, API retries, and suspected
anti-cheating cases remain in the provenance; suspected cases are never
silently dropped to improve a score.

For v4 artifacts, the merger also accepts explicitly failed agent runs without
pretending they succeeded. It requires consistent failure/timeout counts,
permits an unobserved model identity only on a failed task, retains the empty
prediction in cohort order, and rejects any observed model mismatch. Wall
duration, provider duration, cost, tokens, turns, and patch bytes are
aggregated without imputing missing provider accounting.
The merger retains adapters for legacy v2 and v3 artifacts; new runs always
emit v4.

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
model ID, Claude Code version, feedback mode and budget, prediction file, and
evaluator summary together. Evaluate A and B independently on the same ordered
tasks and report `delta FuncPass`, `delta SecPass`, duration, cost, patch size,
regressions, and timeouts. Never use the union of successful cases as a score.
Use at least two independent full runs before interpreting a small score
difference; the public methodology reports meaningful run-to-run variance.

## Validated scorecard

Once official `summary.json` files exist, validate them against the frozen
cohort and build a create-only multi-run scorecard:

```powershell
python scripts/score_susvibes_agent.py `
  --experiment-manifest F:\belief-rd\results\susvibes-experiment-001.json `
  --dataset F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --cohort full `
  --summary F:\belief-rd\susvibes-main\logs\eval\repeat-a\none\belief-claude-hook__MODEL\summary.json `
  --summary F:\belief-rd\susvibes-main\logs\eval\repeat-b\none\belief-claude-hook__MODEL\summary.json `
  --label repeat-a `
  --label repeat-b `
  --output F:\belief-rd\results\belief-full-scorecard-001.json
```

The scorecard rejects mismatched counts, ratios, task IDs, overlapping failure
states, and any `SecPass` set that is not a subset of `FuncPass`. It reports
per-run Wilson intervals, run-to-run range, pairwise SecPass Jaccard overlap,
and union/intersection diagnostics. The union is explicitly not a leaderboard
metric.

The versioned comparator snapshot dated 2026-07-23 records Cursor + Claude
Fable 5 at 29% `SecPass`, Claude Code + Fable 5 at 19%, and Codex + GPT 5.6 Sol
at 23.5% on the Agent Security League. On the 186-task public v1.0 corpus,
54 `SecPass` cases numerically exceed 29%; 67 are needed for the lower bound of
the descriptive 95% Wilson interval to exceed 29%. These are engineering
thresholds only, not proof of a direct leaderboard win.

The 24-case canary deliberately maximizes breadth across CWE strata and
projects; it is an engineering signal, not a prevalence-weighted leaderboard
estimate. Tune only against that canary, then evaluate the disjoint holdout
without further changes. The holdout is a generalization check, not a direct
leaderboard score. Only the complete pinned public cohort evaluated with
official `FuncPass` and `SecPass` tests is the public-v1 headline result.

## Comparability rules

A claim against the Agent Security League requires the same 200-task set,
anti-cheating policy, one attempt per task, and official `SecPass` semantics.
The public SusVibes v1.0 repository currently contains 186 tasks after removing
14 brittle cases, so a local v1.0 result must be labeled as such and must not be
presented as a direct 200-task leaderboard win.

Kimi K3's reported 23/26 result is also not directly comparable: it uses a
private, known-CVE, pass@3 benchmark with a specialized multi-agent harness:
<https://www.aikido.dev/blog/benchmarking-ai-models-known-cves>.
