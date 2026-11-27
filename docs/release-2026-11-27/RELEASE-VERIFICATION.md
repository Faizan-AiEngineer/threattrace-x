# ThreatTrace X release verification

27 November 2026 · Local Windows release candidate · Synthetic Orchid demonstration

## Run the workbench

Follow the [README’s local demo instructions](../../README.md#installation-and-local-demonstration) to start the workbench on [http://127.0.0.1:5173/](http://127.0.0.1:5173/). The installed demo uses a password chosen at setup and a dedicated local SQLite profile. The release walkthrough used a separate production preview and synthetic evidence.

## Before and after

| Area | Previous audit | Release candidate |
| --- | --- | --- |
| Timeline CSV | One filtered event was visible while the CSV included 25 case events. | Timeline and CSV share the same search, category, severity, host, account, evidence and UTC bounds. CSV includes all matches across pages. Chrome exported only the one filtered event. Reports labels its separate full-case timeline CSV. |
| Investigation context | Global shortcuts selected the first case on each new view. The findings shortcut displayed Overview in the breadcrumb. | Shortcuts carry the active case across views and reload within the same browser tab. Opening a case directly sets the context after access is confirmed. A new session with no saved case prompts for selection. Breadcrumbs identify the case and view. |
| Workbench and mobile | Muted headers, compact KPIs, a bare numeric analysis input, and tab, table and graph overflow at phone widths. | More legible KPI hierarchy and explicit UTC chart scope. Case metadata and the analysis window have visible labels. Evidence provides hash copy and clearer custody records. A mobile case-view picker, collapsible timeline filters, compact record cards, and keyboard-menu dismissal ease navigation. Failed record loads offer retry. |
| Correlation | Similar event nodes, limited provenance emphasis and horizontal scrolling on phones. | Type-specific icons, shapes and colors, record-specific event labels, solid observed arrows, dashed inferred arrows and dotted source associations. Zoom, drag and keyboard pan, fit, filters and the detail pane connect back to original files and events. Selection highlights supporting associations. |
| Access administration | Grant and revoke controls with no view of current grants or account lifecycle controls. | View current case grants and ownership. Grant and confirm revoke from Settings. Account disable and reset require administrator reauthentication and revoke sessions. Temporary passwords must be replaced before opening case data. Lifecycle and case grant changes appear in access activity. |
| Swagger | 44 operations in a single default group. | All 44 original operations and seven new operations use ten categories, with descriptions, response contracts, cookie authentication and synthetic request examples. The write safeguard header is visible in Swagger. |
| Research | Saved results with one chart and the primary-run output. | Recorded precision, recall, F1 and false-positive rates, detection and correlation baselines, runtime and correlation timing, and five-seed summaries. Experimental conditions and limitations remain alongside the measurements. |

See the [v0.1.0 documentation and captures](../screenshots/README.md) for the before state.

## Verification

| Check | Result |
| --- | --- |
| Backend | 31 pytest tests passed, including shared filtering and export scope, grant isolation and idempotence, disable and forced reset, migration of existing accounts and grants, graph provenance, local-only demo safeguards, and OpenAPI contracts. Ruff passed. Starlette test-client emitted one dependency deprecation warning. |
| Frontend | ESLint, TypeScript type-checking, and the production Vite build passed. |
| Chrome tests | Eight Playwright tests passed on installed Chrome against an isolated synthetic database. Covered case intake, evidence integrity and custody, findings and reports, filtered CSV, workspace and breadcrumb stability, graph controls, mobile navigation and account management. |
| Chrome release walkthrough | Chrome 158.0.8127.88 rendered the production preview. The run logged 30 page and shortcut checks and 18 layout checks at widths of 390 and 768 px, with no uncaught page errors or unexpected API failures. A separate Chrome check verified mouse-drag pan and Fit graph, and rendered all ten Swagger categories. [Browser verification log](browser-verification.json) |
| Exports and evidence | SHA-256 verification returned a match, custody verification succeeded, the filtered CSV matched the visible event, an HTML report rendered in Chrome, and the PDF had a valid PDF signature. |
| Dependencies | npm audit reported zero known advisories. The first Python scan found advisories in the local pip installer. Updating the project virtual environment from pip 24.3.1 to 26.3 resolved them. pip check and the repeat pip-audit passed. Application dependency pins were preserved. |
| Secrets | Gitleaks 8.30.1 reported no findings in Git history and publishable working-tree text. The ten screenshots use only the fresh synthetic case data and exclude browser chrome and authentication input. |
| Research preservation | `research/results` and `research/figures` match the repository baseline. Chrome compared the exported JSON rows with the served result rows and verified 26 conditions, five seeds and five recorded multi-seed baseline summaries. |

## Screenshot gallery

These ten unaltered 1920 × 1080 captures show the production preview and its generated HTML report. The selected threat intelligence and graph views show only connections and evidence supplied by the application’s synthetic records.

| File | View |
| --- | --- |
| [01-security-overview.png](screenshots/01-security-overview.png) | Investigation KPIs, recorded event volume, severity, and recent activity |
| [02-investigation-case.png](screenshots/02-investigation-case.png) | Case scope, status, analysis controls and auditable activity |
| [03-evidence-integrity.png](screenshots/03-evidence-integrity.png) | Preserved bytes, SHA-256, parser results and verification history |
| [04-chain-of-custody.png](screenshots/04-chain-of-custody.png) | Verified custody records and hashes |
| [05-incident-timeline.png](screenshots/05-incident-timeline.png) | UTC incident order, event distribution, filters and export |
| [06-correlation-graph.png](screenshots/06-correlation-graph.png) | Typed nodes, relationship legend and evidence detail |
| [07-threat-intelligence.png](screenshots/07-threat-intelligence.png) | Synthetic indicator with exact-match references |
| [08-finding-confidence.png](screenshots/08-finding-confidence.png) | Finding rationale, weighted confidence and supporting events |
| [09-research-benchmarks.png](screenshots/09-research-benchmarks.png) | Recorded correlation baselines, precision, recall and F1 |
| [10-investigation-report.png](screenshots/10-investigation-report.png) | Generated case report opened in Chrome |

### Recommended LinkedIn sequence

1. **01 Security overview** for the platform and synthetic demo context.
2. **03 Evidence integrity** for a concrete forensic control.
3. **06 Correlation graph** for the interactive investigation workflow.
4. **08 Finding confidence** for the evidence behind an assessment.
5. **09 Research benchmarks** for recorded synthetic measurements and baseline comparisons.

## Publication verdict and remaining limitations

The source, synthetic walkthrough, documentation and screenshots are ready for a public project release following repository-owner review. The supported deployment remains a trusted local Windows workstation on loopback. A shared production service still needs HTTPS and secure-cookie deployment, authentication rate limits, organization identity and account recovery, encrypted storage and managed backups, independent audit anchoring, and concurrent-load and security validation. Administrators deliver temporary passwords through a trusted channel. The custody chain detects changes relative to its stored head and count. No independently timestamped or external immutable record is configured.

Large graphs show a bounded subset of event relationships. Investigators can narrow or expand the view, and the supporting evidence remains case-scoped. Research uses recorded synthetic conditions. The results do not establish effectiveness on real investigations or in enterprise-scale deployments. The responsive checks exercised Chrome layouts and keyboard paths. A full assistive-technology and cross-browser assessment remains open.

The repository’s [Verify workflow](https://github.com/Faizan-AiEngineer/threattrace-x/actions/workflows/verify.yml) records hosted CI status.
