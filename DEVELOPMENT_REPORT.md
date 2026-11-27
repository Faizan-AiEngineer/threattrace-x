
# ThreatTrace X development report

**Version 0.1.0** · **24 November 2026**

## Project status

The Windows-native SQLite research prototype includes the case and role model, evidence vault, SHA-256 checks, hash-linked custody, nine intake formats, normalized events, chronology, local intelligence, rule detections, correlation review, offline network summaries, evidence confidence, structured exports, and a research workspace. The verified backend uses SQLite. The React frontend uses the actual API. The repository includes an Alembic migration, scripts, a reproducible generator, five synthetic cases, an offline capture, a case study, documentation, and twelve rendered application screenshots.

Limits of the initial release include synchronous parsing and analysis, heuristic rules, bounded graph candidates, selected Windows and syslog formats, and a workstation trust model. Some detection categories rely on source flags or change markers. Native EVTX, PostgreSQL operation, remote hosting, continuous integrity monitoring, external custody anchoring and real-evidence deployment validation are outside the verified scope. The public-release license selected for the repository is MIT.

## Verification

| Check | Result |
| --- | --- |
| Backend pytest | 23 passed, 0 failed, 0 skipped |
| Chrome Playwright integration | 5 passed, 0 failed, 0 skipped |
| Windows startup | Combined startup and isolated test startup verified |
| Lint and types | Ruff, ESLint and TypeScript passed |
| Frontend production build | Vite build passed |
| Dependency audit | pip-audit reported no known vulnerabilities in runtime dependencies. npm reported zero vulnerabilities. |
| Security cases | Role and case separation, expiration, loopback Host and Origin checks, per-case limits, malformed numeric and Unicode records, basename sanitation, hash and custody edits, title-safe exports, and authorization-sensitive controls exercised |
| Artifact QA | 12 desktop and mobile screenshots, real HTML export, and three rendered PDF pages visually reviewed |

The installed Starlette test adapter emitted a deprecation warning about its HTTPX backend. Offline PCAP analysis passed with the existing Windows installation and six captured synthetic DNS packets.

## Research

Seven experiments produced 26 measured conditions. Combined detection reached precision 0.818, recall 1.000 and F1 0.900. Independent-source detection reached F1 0.889 with one fewer false positive and one missed label. Evidence-aware pair correlation reached F1 0.789 versus 0.333 for time-only correlation. At 50% evidence removal, pair recall was 0.278. All five integrity conditions passed. Baseline replays at seeds 11, 23, 42, 71 and 109 yielded identical scores, with sample standard deviations of zero. CSV and JSON were reconciled against the measured outputs and the classification metrics were recalculated from the confusion counts. [Individual seed results](research/results/multi-seed.json)

The 100,000-event benchmark measured 85.90 seconds, including 20.05 seconds for graph processing, and peak traced Python allocations of 255.20 MiB. This benchmark measures normalization and graph construction with allocation tracing. The results cover labeled synthetic fixtures. They do not establish production accuracy or throughput. See [full measurements](BENCHMARKS.md), [CSV](research/results/results.csv) and [reproducibility instructions](research/README.md).

## Storage

| Item | Initial | End-of-run sample |
| --- | ---: | ---: |
| C: free | 4.58 GiB | 4.58 GiB |
| D: free | 97.42 GiB | 97.41 GiB |

The project used approximately **300 MiB**, including **110 MiB** for the Python environment and **179 MiB** for npm dependencies. The Python package cache used 43 MiB, the npm cache used 308 MiB, and the Python bytecode cache used 74 MiB in the initial tool directory. These are logical file sizes. The project, test data, dependency environments, and configured caches were placed on D:. Free-space snapshots include activity from the rest of the workstation.

## Application access

For current installation and the isolated demo launcher, follow the [project README](README.md#installation-and-local-demonstration). The test runner launches separate temporary verification services.

## Publication readiness

Release verification uses the configured GitHub Actions workflow on the published commit. Runtime databases, local evidence, credentials, dependencies and caches are excluded from version control.

The proposed GitHub name is `threattrace-x`. Suggested description is “Evidence-aware digital forensics platform for incident reconstruction, forensic correlation, evidence integrity verification and reproducible cybersecurity research.” Suggested topics include `digital-forensics`, `incident-response`, `network-forensics`, `threat-intelligence`, `mitre-attack`, `fastapi` and `react`. See [the workflow](.github/workflows/verify.yml), [screenshots](docs/screenshots/README.md) and [repository README](README.md).

## Research paper readiness

The project supports a methods or prototype paper with a reproducible synthetic evaluation. A paper claiming practical forensic effectiveness still needs held-out labeled cases, a broader baseline comparison, sensitivity analyses that change the underlying scenarios, and a related-work review. The current measurements do not establish scientific novelty, production performance or legal evidentiary value.
