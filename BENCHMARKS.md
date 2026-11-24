
# Benchmarks

Seed 42. The experiment ran on Windows with Python 3.13.2. The stored artifacts include all 26 measured conditions, confusion counts, configuration and host metadata. [CSV](research/results/results.csv) · [JSON](research/results/results.json) · [Methodology](research/README.md)

## Detection and correlation

| Task | Method | Precision | Recall | F1 | FPR |
| --- | --- | ---: | ---: | ---: | ---: |
| Case/rule detection | Platform rules | 0.818 | 1.000 | 0.900 | 0.0435 |
| Case/rule detection | Independent sources | 0.889 | 0.889 | 0.889 | 0.0217 |
| Event-pair correlation | Source-isolated | 0.000 | 0.000 | 0.000 | 0.0056 |
| Event-pair correlation | Time-only | 0.200 | 1.000 | 0.333 | 0.0225 |
| Event-pair correlation | Evidence-aware | 0.652 | 1.000 | 0.789 | 0.0030 |

Combined analysis recovered one case/rule label beyond the independent-source baseline and added one false positive. The correlation fixture contained 90 expected pairs and 16,020 negatives. The evidence-aware method recovered all 90 pairs and returned 48 false-positive links. Shared benign context was a deliberate distractor. [Correlation figure](research/figures/correlation-f1.svg)

## Evidence loss, clock skew and integrity

- With 10%, 25%, and 50% of records removed, original-ground-truth recall fell to 0.789, 0.511, and 0.278. F1 fell to 0.706, 0.558, and 0.385. [Missing-evidence figure](research/figures/missing-evidence-f1.svg)
- Injecting +30 or +90 seconds on the network source introduced 122 strict pairwise ordering inversions in either condition. At +90 seconds, F1 dropped to 0.411. Applying the known −90-second correction restored the original order and 0.789 F1.
- All five integrity checks passed, including altered bytes, an edited custody entry, and a missing tail record.
- Confidence was 87 for one source, 100 for corroborating sources, 86 when one of the two corroborating sources fails its integrity check, and insufficient for no evidence. These are heuristic scores.

## Scaling

| Events | Runtime (s) | Correlation (s) | Events/s | Peak traced Python memory (MiB) |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 0.62 | 0.23 | 1,623 | 2.97 |
| 10,000 | 3.88 | 1.39 | 2,580 | 25.71 |
| 50,000 | 36.63 | 14.38 | 1,365 | 127.84 |
| 100,000 | 85.90 | 20.05 | 1,164 | 255.20 |

Measurements include allocation tracing and exclude storage writes, HTTP and rendering. They represent one synthetic run at each size, collected while release verification was also running on this workstation. The fixtures and class distribution limit the applicability of precision, FPR and throughput to real investigations.

## Five-seed baseline replay

| Task | Method | Mean F1 | Sample SD |
| --- | --- | ---: | ---: |
| Correlation | evidence-aware | 0.789 | 0.000 |
| Correlation | source-isolated | 0.000 | 0.000 |
| Correlation | time-only | 0.333 | 0.000 |
| Detection | independent sources | 0.889 | 0.000 |
| Detection | platform rules | 0.900 | 0.000 |

Seeds 11, 23, 42, 71 and 109 yielded identical baseline scores. Randomization changes ephemeral ports and timing within the templates. Every labeled positive in the pair fixture is cross-source, so the source-isolated comparison has zero attainable recall. [Individual results and summary for all metrics](research/results/multi-seed.json)
