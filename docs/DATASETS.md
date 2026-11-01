# Dataset strategy

| Source | Adapter / role | Labels and terms |
| --- | --- | --- |
| [OTRF](https://github.com/OTRF/Security-Datasets) | Windows JSONL; documented detection cases | Scenario context is not event truth. Current project LICENSE is MIT. |
| [EVTX Attack Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Export EVTX using the Windows collector | Technique-level context; project GPL-3.0. |
| [LANL](https://csr.lanl.gov/data/cyber1/) | Authentication CSV/GZ + optional redteam.txt | Sparse known compromises; remaining records unknown. CC0. Relative timestamps and filtered failure collection. |
| [BOTS v3](https://github.com/splunk/botsv3) | Export compatible events from Splunk | Pre-indexed release, not a training CSV. Project CC0. |
| [HAI](https://github.com/icsdataset/hai) | Timestamp + numeric-tag + attack-label CSV | Publisher normal/attack periods. README says CC BY-SA 4.0; metadata table says CC BY 4.0. Record and clarify the version's terms. |
| [SWaT/WADI](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/) | Normalize the selected release to ICS CSV | Free by request; iTrust prohibits sharing the received data. |
| [OpTC](https://github.com/FiveDirections/OpTC-data) | Normalize a bounded eCAR subset to canonical events | Public-domain release statement; approximately 1 TB compressed and documented errata. |

The quick OTRF import uses its documented Covenant DCSync host capture. The
application records the downloaded payload SHA-256, not a claim that every
event in it is malicious.

The HAI Kaggle publisher is `icsdataset/hai-security-dataset`, linked by the
original repository. Public file listing/download is supported; optional
server-side credentials are used when configured. Large files need bounded
local slices to fit the import limit.

## Preserve provenance

Every import has a manifest with source, format, original URL when provided,
licence, timestamp, payload hash, inserted-event counts, labels, and parser notes.
The original payload stays locally under `data/imports/<sha256>.payload`.
Events retain their raw record and its own SHA-256. Duplicate records are not
inserted twice. Label changes require a reviewer and a reason and update the
manifest counts transactionally.

## Match the learning problem

- Permission auditing uses explicit business policy, not learned "usual access".
- Authentication models require compatible authentication windows and verified
  normal data. Unlabelled LANL activity is not automatically normal.
- ICS models use one matching source/schema. Do not splice HAI and LANL timelines
  into a purported IT-to-OT campaign.
- Report generation retrieves evidence and policy context. Training a language
  model would require separate, human-reviewed evidence-to-report pairs.

Use individual imports or same-source cohorts in Research. Group boundaries,
feature names, and held-out outcomes are exported with the model. A capture with
only one independent run is useful for detection testing but cannot establish a
leakage-safe train/validation/test benchmark by randomly shuffling its events.

## Canonical event

```json
{
  "timestamp": "2026-11-01T12:00:00Z",
  "kind": "auth_failure",
  "actor": "northstar\\user1",
  "host": "ns-dc01",
  "source_host": "ns-ws01",
  "run_id": "independent-run-001",
  "label": "unknown",
  "data": {"event_id": "4625", "logon_type": "3"}
}
```

Missing labels remain unknown. Supported behavior kinds are visible in the
detection engine and the simulator. A normalized event should report the
observable behavior without setting `malicious` merely because a rule matched.
