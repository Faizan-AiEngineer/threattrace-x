
# Synthetic datasets

The deterministic generator uses only documentation IP ranges, .example names and fictional Orchid Research accounts. It produces cases for suspicious account access, unexpected privilege changes, unusual outbound communication, flagged file access and authorized maintenance. Each case has an identity export and an observations export. Fixtures include an exact repeated record and an uncertain timestamp. Controlled missing records, clock skew and integrity damage are applied by the evaluation runner.

```powershell
. .\scripts\common.ps1
Push-Location backend
& $Python -m app.demo generate --seed 42 --output ../datasets/generated
Pop-Location
```

Outputs include ground-truth JSON and a small six-packet DNS capture. The capture is constructed and written directly to disk. The generator transmits no packets. Run `seed-demo.ps1` to import the scenarios into a local evidence vault and run initial analysis.
