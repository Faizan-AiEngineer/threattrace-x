
# Threat model

## Assets and trust boundaries

Assets include original bytes, case and account metadata, audit records, findings, and exported reports. The browser, API, local filesystem and offline parser each form a boundary. A trusted OS operator controls the workstation, database, evidence directory and environment settings.

| Threat | Implemented control | Residual risk |
| --- | --- | --- |
| Unauthorized case access | Login, case predicates, case-scoped IDs, expiring tokens, admin checks for global rules and account creation | Administrator and OS operator have broad visibility. Local login lacks persistent throttling. |
| Malicious upload | File and request limits, bounded events, format-specific passive decoding, no execution | Vulnerabilities in dependencies may remain. Parser runs in the service process. |
| Traversal and unsafe file access | Generated vault filenames, original filename reduced to display basename, attached authorized downloads | A writable vault and hostile OS operator are out of scope. |
| SQL injection | Bound SQLAlchemy expressions, typed query inputs and allowlisted sorting | Future raw SQL needs an independent review. |
| Cross-site scripting or request forgery | JSX escaping, escaped HTML export, same-origin proxy, loopback Host allowlist, explicit CORS/Origin checks, required write header, HttpOnly cookie | Compromise of the local frontend permits abuse of the logged-in session. |
| Evidence tampering | Streaming SHA-256, check history, manual integrity verification and analysis exclusion after failure | No continuous checking or external cryptographic timestamp. A database writer can change both references. |
| Audit-log modification | Custody sequencing plus hash chain, head and count checks, transactionally recorded application actions | The general audit table is separate from custody. No external signature, remote anchoring or WORM storage. |
| Resource exhaustion | Request, per-case evidence storage and event limits, graph display caps and streaming custody verification | Large allowed cases can consume memory and hold the SQLite write lock. |
| Sensitive disclosure | Role checks, loopback, no automatic external lookups, excluded runtime data, attachments and restricted caching | Created exports are controlled by the analyst. Local data and backups need OS encryption and file permissions. |

Review dependencies before release and keep testing data separate from investigative data. Avoid publishing real evidence or screenshots that contain it.
