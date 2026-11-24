
# Orchid Research account-access case

**Synthetic exercise.** The Windows-native SQLite prototype was used to review sign-in records and analyst observations associated with the fictional Orchid gateway. The investigation focused on the account named analyst-1 and the source address 192.0.2.20.

The investigator opened the seeded case **Suspicious account access**, confirmed the two expected sources in Evidence and verified their SHA-256 hashes. The custody view reported a valid chain for each evidence item. The identity export contained the failure sequence starting at 14:04:00 UTC on 8 April 2025. The second source contained a success at 14:05:01 UTC and an administrative event at 14:05:30 UTC. The observation file also contained a repeated record and a collection-gap record with uncertain time.

With a 300-second window, the rule engine produced repeated-authentication-failure, successful-follow-up and flagged-administrative-activity findings. The follow-up finding linked both files. The correlation view showed shared account, host and IP context, and its inferred links could be reviewed individually. The investigator could trace each event to a numbered source record. The generated case report includes evidence provenance, parser and inventory information, findings, confidence and limitations.

A plausible next step in the fictional investigation would be to reconcile the sign-in sequence against independent identity-provider and change-management logs before confirming account misuse. The benign maintenance scenario demonstrates why this matters. Its authorized workflow produces two suspicious rule hits under the same threshold policy.
