# BELIEF v4 hotfix #3.1 — CORRECTIVE for hotfix #3 sample metadata

## The bug

The 3 multi-file CVE samples I shipped in hotfix #3 had **incorrect line
numbers in their metadata.json**. I had miscounted lines (the docstrings
at the top of each file shifted the sink line down by 2–5 lines from
what I declared).

Bandit/dlint/path_traversal found the sinks CORRECTLY in your benchmark
run — line 16 for SQLi, line 14 for RCE, line 18 for traversal. The
benchmark marked them as FP (false positive) because the metadata said
"the sink is at lines 14, 10, 13" so the `±1` tolerance window missed
the real findings.

## Before this fix (your last run)

```
=== multi-file (3) ===
  detected 0/3, TP=0 FP=6 findings=6 prec=0%
  cwe_22_traversal_multifile: TP=0 FP=1 missed=True
  cwe_78_rce_multifile:       TP=0 FP=4 missed=True
  cwe_89_sqli_multifile:      TP=0 FP=1 missed=True
```

## Expected after this fix

```
=== multi-file (3) ===
  detected 3/3, TP≈3 FP≈3 findings=6 prec=50%
  cwe_22_traversal_multifile: TP=1 FP=0 missed=False  (line 18 match)
  cwe_78_rce_multifile:       TP=2 FP=1 missed=False  (line 14 match on B602 + DUO116, B404 noise remains)
  cwe_89_sqli_multifile:      TP=1 FP=0 missed=False  (line 16 match)
```

**Net benchmark after 3.1**: recall will jump from 77% to 100% (13/13).
Precision gets dragged down a bit because each multi-file sample still
has some bandit-level noise (B404 subprocess-import FP is a known issue
noted since hotfix #2).

## Files changed (4)

| File | What changed |
|---|---|
| `benchmark_cve/cve_samples/cwe_89_sqli_multifile/metadata.json` | `vulnerable_lines`: 14 → 16 |
| `benchmark_cve/cve_samples/cwe_78_rce_multifile/metadata.json` | `vulnerable_lines`: 10 → 14 |
| `benchmark_cve/cve_samples/cwe_22_traversal_multifile/metadata.json` | `vulnerable_lines`: 13 → 18 |
| `benchmark_cve/cve_samples/cwe_78_rce_multifile/generators/report.py` | `out_dir = "/tmp/reports"` → `os.path.expanduser("~/reports")` — eliminates bandit B108 FP on hardcoded /tmp path |

## How to apply

```bash
cd /mnt/c/Users/tatam/Desktop/BELIEF_V2/belief_v4
unzip -o /path/to/belief_v4_hotfix3.1.zip

# re-run
source .venv/bin/activate
python3 benchmark_cve/run_benchmark.py --full
```

## Observations sur ton dernier run

**Bonne nouvelle : tout le reste marche.** Les single-file samples sont
toujours à 10/10 détectés avec 89% précision. Les bridges trouvent
correctement les sinks dans les multi-fichiers — c'est juste mon
étiquetage qui cassait le scoring.

**CWE-918 SSRF tu ne l'as pas dans ce results.json ?** L'uploaded file
contenait les 13 samples (3 multi-fichiers + 10 single) donc CWE-918 est
là et il est OK. Tu n'as pas uploadé `cognitive_results.json` cette
fois — je ne peux pas confirmer que dec_qual/bel_acc/hyd_eff sont passés
à ~0.95 comme prévu. Upload-le ou relance le bench, ça me dira si Pack E
(contradiction sémantique) + fix SSRF fonctionnent bien dans la loop.

## Next step après 3.1

Vérifie que les 3 multi-fichiers détectent (recall 100%). Ensuite regarde
`cognitive_results.json` pour voir ce que la loop fait sur les
multi-fichiers — c'est LE point intéressant :
- Si la loop fait dec_qual≈1.0 sur les multi-fichiers : la combinaison
  severity-gate + Hydra suffit. Pas besoin d'investir en cross-file
  belief propagation maintenant.
- Si elle fait dec_qual<0.7 : c'est le signal pour coder la propagation
  inter-fichiers (LangGraph/pgmpy).
