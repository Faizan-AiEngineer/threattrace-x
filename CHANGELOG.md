
# Changelog

## 0.2.0 · 2026-11-27

### Investigation workflow

- Export the full set of filtered timeline rows in UTC order. Reports labels the separate full-case export. The export record includes the number of rows, filter names, and the CSV digest.
- Keep the active investigation across workspace changes and reloads. Correct case breadcrumbs and the findings shortcut, and prompt for a case when there is no active selection.
- Improve dashboard charts and KPI legibility, case and evidence details, severity badges, hash verification, custody records, retry states, and mobile navigation.

### Correlation, research and API

- Distinguish events, accounts, hosts, devices, IP addresses, files, and evidence sources in the correlation graph. Add relationship filtering, drag and keyboard pan, zoom, fit, and detail links to supporting records.
- Show recorded precision, recall, F1, false-positive rates, baselines, runtime, correlation timing, experimental conditions, and five-seed summaries. The original research artifacts are preserved.
- Organize 51 operations in ten OpenAPI categories. Add endpoint descriptions, typed responses, local session authentication, and synthetic request examples.

### Accounts and demo

- Show existing case grants and access activity. Administrators can disable accounts or reset passwords after reauthentication. Both actions revoke existing sessions. A reset requires a new password before accessing cases.
- Isolate the synthetic demo in a dedicated SQLite profile. The launcher prompts for a locally chosen demo-only password and binds both services to loopback. The demo backend rejects remote clients, non-loopback browser origins, and external database configuration.
- Add backend and browser regressions for filtered export, case context, graph interaction, grants, session revocation, local-only demo behavior, and account migration.

The supported deployment is a trusted local workstation. Use the synthetic profile for demonstration and keep authorized evidence in a separate private profile. See the [release verification](docs/release-2026-11-27/RELEASE-VERIFICATION.md) for checks and screenshots.

## 0.1.0

- Windows-native case workspace with authentication, case sharing and a versioned API.
- Preserved evidence, SHA-256 verification, custody history and source-aware parser registry.
- Rule detections, confidence assessment, event correlation, timeline and offline network analysis.
- Local indicator management and PDF, HTML, JSON and CSV reports.
- Synthetic scenarios, research evaluation, measured results, screenshots and CI configuration.
