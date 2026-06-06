# benchmark_reportability

`benchmark_reportability` is a small offline MVP corpus for evaluating BELIEF's
reportability behavior.

It is intentionally metadata-ground-truth based. The benchmark runner reads the
`cases.yml` files, compares expected and observed verdict labels, and computes a
deterministic summary. It does not run scanners, execute fixtures, import
fixtures, make HTTP requests, call LLMs, or prove real-world vulnerability
discovery.

The corpus focuses on conservative reportability categories:

- `reportable_candidate`
- `needs_manual_validation`
- `weak_signal`
- `likely_false_positive`
- `protected_by_guard`

The fixture snippets are synthetic and local. They are examples for explaining
why a case might be reportable, protected by a guard, weak, or likely false
positive. Manual validation in authorized scope is still required before making
any real security claim.

Run the MVP benchmark:

```bash
python -m belief benchmark reportability --target benchmark_reportability --json-output out/benchmark.json
```

The output uses schema version `belief.benchmark_reportability.v1` and mode
`metadata_ground_truth_mvp`.
