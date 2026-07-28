# Local validation benchmark

This directory is independent from every SusVibes artifact and cohort. Its
transparent corpus contains only eight controlled local fixtures:

| Family | Vulnerable | Protected | Ambiguous | Trap |
|---|---|---|---|---|
| path traversal | unchecked join | resolved boundary | unavailable entrypoint | safe implementation behind a static positive |
| IDOR/BOLA | authentication only | owner and tenant enforced | unavailable entrypoint | safe implementation behind a static positive |

`ground_truth: ambiguous` is excluded from binary precision and recall, but
remains in the abstention denominator. A vulnerable case that receives
`negative` or `abstain` counts as a missed positive for recall.

Run:

```bash
python scripts/benchmark_local_validation.py \
  --corpus benchmark_validation/cases.json \
  --output out/local-validation-benchmark.json
```

The report is create-only and records that it used no network, subprocess,
Docker, external system, reserved holdout, or SecPass-equivalent measurement.
