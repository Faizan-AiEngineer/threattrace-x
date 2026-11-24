
# Data dictionary

Text identifiers are application-generated unless a table uses a rule code. UTC timestamps are ISO 8601 strings with a UTC offset and microseconds. Integer sizes count bytes. JSON is used for source metadata, weighted confidence, parser statistics and descriptive relationship attributes.

| Table | Main fields and constraints |
| --- | --- |
| users | id, unique username, scrypt password_hash, role, created_at |
| sessions | SHA-256 token digest id, indexed user_id, indexed expires_at |
| cases | id, owner_id, investigator, title, description, classification, severity, indexed status, synthetic, created_at, updated_at |
| case_access | id, case_id, indexed user_id; unique pair |
| evidence | id, indexed case_id, filename, size, format, sha256, collection_at, imported_at, source, uploader, custodian, integrity, parser_version, state, stats, clock_offset seconds, timezone_offset minutes, custody_count, custody_head; unique case_id and sha256 |
| evidence_verifications | id, indexed evidence_id, actor, timestamp, actual_hash, status |
| custody | id, indexed evidence_id, sequence, actor, action, timestamp, reason, previous_hash, record_hash; unique item and sequence |
| events | id, case_id, indexed evidence_id, source_ref, UTC timestamp, original_timestamp, time_quality, source_type, category, action, hostname, username, IP and port pairs, protocol, process_name, process_id, file_path, file_hash, domain, url, bytes, outcome, severity, metadata, clock_offset; unique evidence and source_ref; indexed case chronology |
| entities | id, indexed case_id, kind, value; unique case, type and value |
| entity_events | id, indexed entity_id and event_id; unique pair |
| relationships | id, indexed case_id, source_id and target_id event references, kind, attributes, explanation, confidence, version, review, reason, active; unique case and event pair |
| rules | rule code id, enabled, threshold, window seconds |
| findings | deterministic id, indexed case_id, rule_id, version, name, severity, stage, explanation, steps, limitations, technique, confidence, timestamp, active, review_reason, override |
| finding_events and finding_evidence | id, indexed finding_id, referenced event_id or evidence_id; unique pair |
| indicators | id, indexed case_id, kind, value, source, confidence, description, created_at, expires_at, tags; unique case, type and value |
| indicator_matches | id, indexed case_id, indicator_id, event_id; unique pair |
| notes | id, indexed case_id, optional event_id, actor, timestamp, body |
| reports | id, indexed case_id, actor, timestamp, format, exported byte sha256 |
| audit | id, optional indexed case_id, actor, action, timestamp, detail |
| research_experiments | id, timestamp, seed, results JSON |

Intake allows up to 200 evidence files, 128 MiB of original bytes and 100,000 normalized events per case. Evidence custody head and count are read in the same SQLite snapshot as the chain.

A source reference uses `record:N` for a JSON event position, `line:N` for a text/CSV source, and `packet:N` for an offline capture. Missing or unparsed times have a null corrected timestamp. Naive timestamps use the intake offset and are marked assumed. Explicit timestamps preserve the supplied zone in original_timestamp. For records with no usable clock information, original_timestamp retains the source value when present.
