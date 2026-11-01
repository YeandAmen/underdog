# Architecture

```text
Windows JSON / canonical JSONL / LANL CSV / ICS CSV
                         │
                  Go normalizers
              raw payload + SHA-256 manifest
                         │
                    SQLite / WAL
                         │
      ┌──────────────────┼────────────────────┐
      │                  │                    │
  source-bound       detection rules      Go Isolation Forest
  identity policy    + correlations        compatible windows
      │                  │                    │
      └──────────────────┼────────────────────┘
                         │
                 ranked investigations
                         │
           evidence bundle + related events
                         │
         local brief / Agent Router / Ollama
                         │
               cited report + human review
```

## Identity and policy

The snapshot contains users, nested groups, assets, normalized grants, explicit
role/action policies, event-source bindings, and optional independently recorded
change approvals. A public capture with the same account name as a lab user is
not automatically treated as that identity.

Supported actions are `local-admin`, `reset-password`, `write-members`,
`replicate-directory`, `remote-logon`, `read`, and `write`. Grants represent one
already-scoped action. Explicit denies precede explicit allows; inherited ACEs
are evaluated by ancestor distance, deny before allow at each distance.

This is **not a full arbitrary Windows AccessCheck implementation**. Collectors
must resolve object-class and inheritance scope before emitting normalized
grants. Unmodelled GPO rights, cross-forest trusts, token privileges, and complex
multi-principal combinations need richer collectors and validation.

Remediation preview removes a grant from an in-memory copy and displays its
affected identities. It performs no AD write. Removing an unintended membership
edge may be preferable when the grant also serves legitimate users.

## Detection and evidence

Twelve rules inspect observable behaviours. Known ground-truth labels are used
only for evaluation metadata. They never trigger a rule or choose an anomaly
score. Privileged-change tuning requires a separate policy approval matching
the operator, target, group, ticket, source, and time; a ticket string in a log
alone is insufficient.

Directory replication origin is correlated with the authentication logon ID;
the domain controller recording an audit event is not assumed to be its client.
Related evidence shares a source and run and falls within a bounded window.
Temporal association is shown as correlation, not causality.

## Models

Authentication features: failed logons, successful logons, distinct destinations,
remote logons, and distinct sources per actor/run/five-minute window.

ICS features: means of finite numeric tags in non-overlapping five-minute
windows. A column fingerprint identifies the source schema; mismatched schemas
are rejected rather than silently merged. Original units are retained.

Complete runs or collection days are split chronologically 60/20/20. Only
verified benign training windows fit 96 trees. The 95th percentile of benign
validation scores sets the decision threshold. Test labels affect metrics only.
Duplicate evidence cannot enter another split by changing its ID or run name.

Training requires at least ten independent groups, twelve benign training
windows, and three benign validation windows. Undefined metric denominators
produce `null`, not fabricated perfect scores. Models retain their trees,
feature names, seed, groups, data digest, test scores, and comparison metrics.

Persisted models feed inference candidates into the queue. Applying an
authentication model to a new source is not evidence of validated generalization.
Synthetic lab results are explicitly scoped to the controlled corpus.

## Analyst boundary

Agent Router and OpenRouter use the Responses API. Ollama uses its local OpenAI-compatible
chat endpoint. The local brief is a deterministic template, not LLM inference.

Reports receive selected normalized evidence, matched rule descriptions, and
source-bound policy findings. Raw records and truth labels are withheld; secret-
named data fields are removed. At most 120 events enter a report request.
Logs are treated as untrusted data. Reports cannot execute tools or change AD.
Citation IDs are checked against the selected evidence. Semantic truth requires
review. Saved reports are invalidated when their evidence/policy digest changes.

## Runtime

`net/http` serves the original HTML/CSS/JavaScript from `go:embed`. SQLite stores
events, manifests, snapshots, rules, models, reports, and reviewer attribution.
Dataset payloads live under the private data directory. Source downloads are
catalogued or restricted to the authoritative HAI publisher; arbitrary URL
fetching is not exposed.

Workspace API responses are not cached in browsers. Mutation origins are
checked. Optional bearer authentication covers API access; non-loopback binding
requires it. CSP disallows external scripts, framing, and off-origin connections
from the UI. Dynamic log text is escaped before rendering.
