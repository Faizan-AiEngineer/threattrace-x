
# Research methodology

## Research problem

ThreatTrace X studies evidence-aware multi-source forensic correlation and explainable incident reconstruction when logs are missing or clocks disagree. This synthetic evaluation measures behavior under controlled conditions. Related-work research should compare published log correlation, evidence provenance and time synchronization approaches against explicit inclusion criteria before any scientific novelty claim.

## Reproduction

Run `scripts/run-research.ps1 -Seed 42`. The runner uses an isolated local database, reuses the production normalizer and analysis methods, and saves results.json, results.csv and SVG figures. CLI options set the seed, benchmark sizes, and output locations. Results include host implementation and Python version.

For the deterministic baseline replays, configure the D: workspace environment with the common script and run:

```powershell
. .\scripts\common.ps1
Push-Location backend
& $Python -m app.research --repeat-seeds 11 23 42 71 109
Pop-Location
```

[Per-seed results and sample standard deviations](results/multi-seed.json) cover both detection modes and all three pair-correlation methods. Seed changes vary ephemeral ports and event timing within fixed templates. The replays measure reproducibility and offer limited evidence about robustness.

1. **Detection** evaluates binary case/rule labels across five scenario fixtures and every configured rule. The baseline runs the same rules separately on each source. Precision is TP/(TP+FP), recall is TP/(TP+FN), F1 is their harmonic mean, and FPR is FP/(FP+TN).
2. **Correlation** evaluates all unordered pairs in 180 timestamped records. Ninety pairs are labeled positive across 30 groups, each with three contributing sources and three distractors. Source-isolated correlation requires source equality, time-only treats events within 30 seconds as candidates, and evidence-aware requires a contextual inferred graph edge. Every labeled positive is cross-source by construction, so source-isolated correlation has zero attainable recall for this task. Labels are created from scenario membership before scoring. The predictor receives normalized records with opaque event IDs and no label field.
3. **Missing evidence** shuffles the fixture with the stated seed and removes 0, 10, 25 or 50% of records. Original ground truth stays fixed, so pairs made unobservable by removal count against reconstruction recall.
4. **Timestamps** inject a known source clock offset and use pairwise inversion counts relative to the original order. Timestamp ties are excluded from inversions. A corrected condition applies the known inverse offset.
5. **Integrity** compares original and altered file contents and tests clean, edited and tail-truncated custody sequences.
6. **Scalability** measures elapsed wall time, graph time, throughput and Python-traced allocation peak. Input counts go up to 100,000. This run measures normalization and graph processing separately from web requests, SQLite writes, and PDF export.
7. **Confidence** compares a single source, two corroborating sources, conflicting integrity and missing evidence. The conflicting-integrity condition changes only that component relative to the corroborated condition. Integrity is 1/0.5/0 for verified/unverified/failed, timestamp quality is 1/0.5/0 for explicit/assumed/missing or uncertain, completeness is 1/0.5/0 for processed/partial/failed, and corroboration is capped at two source items. Indicator confidence and agreement among support-event links enter when available.

The detection scenarios and rule set were designed together. Upstream flags, action templates and the selected indicator are strong synthetic cues. Labels are kept out of runtime inputs, but the fixture design favors the tested rules. Parameter choices are inspectable, source labels are handcrafted, and results are sensitive to data-generation assumptions. Future work should evaluate heterogeneous logs, weaker cross-source identifiers, uncertain ground truth, calibrated thresholds and a larger range of event densities.
