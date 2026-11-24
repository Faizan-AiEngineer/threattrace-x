
# Application screenshots

These captures use an isolated Windows Chrome session with the local application and the fictional Orchid Research dataset.

| View | Capture |
| --- | --- |
| Investigation overview | [Desktop](01-overview.png) · [Mobile](12-mobile-overview.png) |
| Case workspace | [Investigation](02-investigation.png) |
| Evidence | [Evidence vault](03-evidence-vault.png) · [SHA-256 verification](04-integrity-verification.png) |
| Reconstruction | [Timeline](05-timeline.png) · [Correlation graph](06-correlation-graph.png) |
| Network and indicators | [Network forensics](07-network-forensics.png) · [Threat intelligence](08-threat-intelligence.png) |
| Custody | [Verified history](09-chain-of-custody.png) |
| Research | [Research Lab](10-research-lab.png) |
| Report | [Generated HTML export](11-generated-report.png) |

To repeat the capture, start an isolated seeded workspace and run `node tests/capture.mjs` from the frontend with TTX_TEST_PASSWORD set in the local session. Optional TTX_TEST_USER and TTX_BROWSER_URL target a different local account and address.
