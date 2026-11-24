
# Investigator guide

1. Create a case with a title, scope, investigator, severity and classification. Administrators manage local users and case grants in Settings.
2. In Evidence, select an explicit source type and describe collection context. For timestamps without an offset, supply the source offset in minutes and any independently established clock correction in seconds.
3. Verify the bytes before relying on the evidence. Review parser errors and trace suspicious event records to the original evidence anchor.
4. In Timeline, use UTC or local display. Use the UTC From and Through filters to narrow the interval. Missing or uncertain timestamps appear after dated events when no range is applied.
5. Run analysis to update findings, candidate relationships, case entities and local indicator matches. Review inferred relationships and findings with a reason. Record annotations directly on events or in case notes.
6. Open the custody record to verify its head and sequence or transfer custody to another user with case access.
7. Use Reports for a local export. The report snapshot identifies the source and scope of the recorded conclusions.

## Source formats

JSON and normalized Windows exports accept an object, an array, or an object with an events array. JSONL accepts one object per line. CSV uses a header row. Syslog accepts common ISO and legacy prefixes. Legacy timestamps lacking a year stay marked uncertain. Auth logs recognize OpenSSH password failures and accepted login lines. Web access logs accept common and combined log formats. Zeek supports delimited log exports with a #fields header. Scapy reads small PCAP and PCAPNG captures. Non-IP frames can have empty network identifiers. Encrypted application data can obscure DNS and application metadata.
