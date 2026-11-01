# Workspace API

The browser and CLI use the same Go endpoints. JSON mutations accept one JSON
object; upload uses multipart form data. If enabled, send
`Authorization: Bearer <workspace-access-token>`. Cross-origin browser mutations
are rejected. API keys for model/Kaggle providers are never returned.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Version, health, workspace-token requirement |
| GET | `/api/state` | Counts, source-bound policy, findings, cases, rules, manifests, model summaries |
| GET | `/api/incidents/{id}` | Matching and related evidence, local brief, current saved report |
| POST | `/api/incidents/{id}/report` | `{ "provider": "agentrouter" }` or `local` / configured `ollama` |
| POST | `/api/incidents/{id}/review` | `{ "verdict": "benign", "reviewer": "name", "reason": "independent evidence" }` |
| GET | `/api/events?q=&label=&source=&page=1` | Filtered evidence, 50 records/page |
| POST | `/api/events/{id}/label` | `{ "label": "unknown", "reviewer": "name", "reason": "..." }` |
| POST | `/api/identity/snapshot` | Validated users/groups/assets/grants/policies/source bindings/approvals |
| POST | `/api/identity/preview` | `{ "finding_id": "DRIFT-..." }`; read-only blast-radius preview |
| POST | `/api/rules/{id}` | `{ "enabled": true }` |
| POST | `/api/lab/replay` | `{ "scenario": "identity-to-ot" }` |
| POST | `/api/datasets/import` | Multipart: `file`, `format`, `source`, optional `name`, `license`, `source_url`, `labels`, `verified_normal` |
| POST | `/api/datasets/reprocess/{id}` | Re-normalize the preserved payload; raw hashes and reviewer labels are retained |
| POST | `/api/datasets/fetch/otrf` | Documented publisher DCSync host capture |
| GET | `/api/datasets/kaggle/files` | Public HAI publisher CSV listing |
| POST | `/api/datasets/kaggle` | `{ "file": "hai-20.07/test2.csv" }`; bounded publisher download |
| POST | `/api/research/train` | `{ "domain": "authentication", "dataset_id": "northstar-lab" }`; `ics` and `source:hai` cohorts also supported |
| POST | `/api/ai/check` | Small configured-model connectivity probe |
| GET | `/api/export/events` | Canonical JSONL with provenance |
| GET | `/api/export/report/{id}` | Current report as Markdown |
| GET | `/api/export/model/{domain}` | Persisted model trees and experiment record |
| GET | `/api/stream` | Workspace change/heartbeat server-sent events |

Cases and label reviews remain separate: closing a false positive does not
relabel every event in the surrounding capture. Report exports require a saved
report whose evidence digest still matches the current bundle.
