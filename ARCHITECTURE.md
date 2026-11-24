
# Architecture

## Components

- **API and validation** use FastAPI's versioned router and Pydantic request schemas. Protected endpoints derive case visibility from ownership, an explicit case grant, or administrator privileges.
- **Persistence** uses SQLAlchemy Core with foreign keys, unique lookup keys and an Alembic revision. The supported runtime is local SQLite. Sensitive application state is under runtime or a configured data directory.
- **Evidence** streams each upload to a staged file while hashing, evaluates format-specific parsers, then commits metadata and indexed events under a case-specific checksum constraint. The vault stores generated IDs rather than client paths.
- **Analysis** operates on normalized records. Rule IDs and versions remain attached to findings. Rules identify authentication sequences, privilege and service changes, source-flagged signals, transfer thresholds, local indicators and integrity failures. The engine excludes evidence with a recorded failed integrity check and retains inactive results with reviewer decisions.
- **Presentation** uses versioned JSON endpoints for the desktop and responsive views. Reports render a shared snapshot to multiple formats. The Vite proxy keeps browser requests same-origin by default.

## Evidence lifecycle

Intake validates size, format name and visible metadata. A streaming SHA-256 pass preserves the original data. Parsing emits a source reference per record and reports failures by reference. The local vault is outside the frontend tree. A database error after file rename deletes the staged final file during normal exception handling. A power loss between file rename and database commit can leave an unreferenced file. Compare vault filenames with the evidence register during recovery.

Custody records include an ordered sequence, actor, UTC timestamp, reason and previous hash. Hash material is a sorted-key UTF-8 JSON object with fixed separators. Verification recomputes each record hash and checks the terminal hash and count against the evidence row. The evidence register and database are trusted local references.

## Correlation and scoring

The engine processes dated events chronologically. Candidate indexes cover account, host, IP address, host-scoped process ID, process name, file path/hash, domain, URL, matching indicator, and shared evidence. Each index keeps six recent candidates. Up to four relationships enter an event per run. A shared source generates an observed relationship. Shared attributes within the window generate a reviewable inference. Analysts can confirm or reject a relationship with a reason. The recent-candidate and edge caps favor tractable investigation views and can omit legitimate relationships in dense traffic.

Confidence is a weighted index from 0 to 100. Use 25% integrity, 20% corroboration, 15% timestamp quality, 10% indicator reliability, 15% correlation consistency, and 15% parser completeness. Let A contain the applicable components. Compute round(100 × sum(weight × value over A) / sum(weight over A)). The detail panel shows each applicable value and weight. Scores of at least 75 are high, at least 45 are moderate, and lower values are low. Absence of evidence returns insufficient. A reviewer may override a score with a reason. See [research methodology](research/README.md) for operational definitions and evaluation limits.

ATT&CK tags are selected rule associations for repeated failures, suspicious follow-up logins, and unexpected privilege changes. Refer to MITRE's [Brute Force T1110](https://attack.mitre.org/techniques/T1110/), [Valid Accounts T1078](https://attack.mitre.org/techniques/T1078/), and [Account Manipulation T1098](https://attack.mitre.org/techniques/T1098/).

## Operational trade-offs

Analysis and report exports are synchronous. SQLite serializes write-side custody sequences and state changes. Long analyses can delay other writers. The parser caps each source at 100,000 records. Intake caps each case at 200 evidence files, 128 MiB of original bytes and 100,000 normalized events. Analysis and report exports enforce the event cap for existing cases. Read-side custody checks use a single SQLite snapshot and verify the chain one row at a time. HTML and PDF summaries cap individual sections at 200 entries. CSV and JSON are available for full machine-readable exports. See [the threat model](THREAT_MODEL.md) for deployment boundaries.
