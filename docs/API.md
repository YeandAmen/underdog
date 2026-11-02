# Workspace API

The browser and CLI use the same Go endpoints. JSON mutations accept one JSON
object; upload uses multipart form data. If enabled, send
`Authorization: Bearer <workspace-access-token>`. Cross-origin browser mutations
are rejected. API keys for model/Kaggle providers are never returned.

The production demo has `IDENTITYSHIELD_PUBLIC_ACCESS=true`, so the browser and
API open without a workspace token. Private deployments keep this setting false.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Version, health, workspace-token requirement |
| GET | `/api/state` | Counts, source-bound policy, findings, cases, rules, manifests, model summaries |
| GET | `/api/incidents/{id}` | Matching and related evidence, local brief, current saved report |
| POST | `/api/incidents/{id}/report` | `{ "provider": "agentrouter" }` or `local` / configured `ollama` |
| GET | `/api/report-jobs/{id}` | Queue/running/completion status and a validated completed report |
| GET | `/api/ai/worker/status` | Repo worker availability and last heartbeat |
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
| POST | `/api/ai/check` | Configured-model probe, or worker connection status in worker mode |
| GET | `/api/export/events` | Canonical JSONL with provenance |
| GET | `/api/export/report/{id}` | Current report as Markdown |
| GET | `/api/export/model/{domain}` | Persisted model trees and experiment record |
| GET | `/api/stream` | Workspace change/heartbeat server-sent events |

Cases and label reviews remain separate: closing a false positive does not
relabel every event in the surrounding capture. Report exports require a saved
report whose evidence digest still matches the current bundle.

## Queued reports and the repo worker

With `UNDERDOG_AI_BACKEND=worker`, a fresh report request returns **202** with
`{ "job": { "id": "JOB-...", "status": "queued", ... } }`. Poll
`GET /api/report-jobs/{id}` until `status` is `succeeded` or `failed`.
Successful jobs include `report`; failures include a brief `job.error`.
Matching saved reports and local briefs return **200** directly.

The Go/OpenCode worker uses a separate `Authorization: Bearer
<UNDERDOG_WORKER_TOKEN>` on these endpoints, including in a public workspace:

| Method | Path | Body |
| --- | --- | --- |
| POST | `/api/ai/worker/heartbeat` | `{ "provider": "agentrouter", "model": "<configured-model-id>" }` |
| POST | `/api/ai/worker/claim` | Same worker identity; returns an evidence-only task, or 204 when idle |
| POST | `/api/ai/worker/jobs/{id}/complete` | `{ "claim_token": "...", "report": { ... } }`, or `error` instead of `report` |

Each claim has an eight-minute lease. Disconnected jobs can be reclaimed with
a fresh claim token; an expired claimant cannot publish. Completion rechecks
the current incident digest and every citation, then atomically saves the job
result and report. Public job responses contain neither claim tokens nor model
requests. An offline worker yields a clear 503 for fresh generation.
