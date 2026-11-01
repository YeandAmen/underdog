# IdentityShield

**Security, in context.** An identity-aware cyber defence workspace built in Go.

IdentityShield connects permission auditing, event detection, trainable anomaly
baselines, and cited investigation reports in one deliberately minimal interface.
The visual direction draws inspiration from [ratneshc.com](https://ratneshc.com/):
restrained typography, thin borders, generous spacing, and light/dark themes.
The application code and artwork are original.

## Start the workspace

Requires **Go 1.26 or newer**. Node is only needed for browser tests.

```sh
git clone https://github.com/YeandAmen/identityshield.git
cd identityshield
go run ./cmd/identityshield serve
```

Open **http://127.0.0.1:8787**.

The first run creates a labelled Northstar synthetic lab, an explicit role policy,
and two persisted Isolation Forest benchmarks. The interface clearly identifies
synthetic data. It does not imply a Windows VM or physical plant is connected.

To begin with an empty workspace:

```sh
IDENTITYSHIELD_DEMO=false IDENTITYSHIELD_DATA_DIR=./data/clean go run ./cmd/identityshield serve
```

## What works

- **Identity auditing:** nested-group expansion with cycle handling; normalized
  grants; explicit/inherited precedence; policy drift and explanation paths.
- **Detection:** twelve transparent rules, rule toggles, source-scoped policy
  context, independently approved change windows, and authentication-to-directory
  replication correlation.
- **Model inference:** persisted Go Isolation Forest models score compatible
  authentication/ICS windows and feed the investigation queue.
- **Investigation:** original evidence, citations, related events, analyst reviews,
  event-level label attribution, and Markdown report export.
- **Datasets:** canonical JSON/JSONL, Windows/Sysmon JSON exports, LANL CSV/GZ with
  optional compromise labels, and ICS numeric-tag CSV. Compatible ZIPs are read
  in memory; original payloads and SHA-256 manifests are retained locally.
- **Research:** chronological, whole-run/day 60/20/20 splits, benign-only fitting,
  validation-set thresholds, held-out precision/recall/AP, transparent z-score
  comparison, seed and feature provenance, and exportable model trees.
- **Reproducible lab:** telemetry scenarios, a Go mass-balance tank simulator,
  Windows event/identity collectors, scoped AD setup, and Hyper-V provisioning.
- **Interface:** responsive layouts, command palette, persistent theme, accessible
  dialogs, source manifests, and a live workspace update connection.

## Agent Router configuration

Create a local `.env` using `.env.example` as a reference. Credentials are only
read by the Go server; `.env`, databases, and downloaded evidence are git-ignored.

```dotenv
AGENT_ROUTER_API_KEY=your-working-key
AGENT_ROUTER_BASE_URL=https://agentrouter.org/v1
IDENTITYSHIELD_AI_PROVIDER=agentrouter
IDENTITYSHIELD_AI_MODEL=gpt-6.1-sol
```

Restart the server after changing credentials. Check the exact model/channel:

```sh
go run ./cmd/identityshield doctor --check-ai
```

The integration uses **POST `/v1/responses`**, following the provider's
[documented configuration](https://agentrouter.org/docs/codex.html). It never
silently substitutes the requested model. HTTP 401/403, unavailable channels,
incomplete responses, malformed reports, and invented citations are surfaced.

**Agent Router is remote inference.** Generating a report sends the selected
normalized evidence and permission context to the configured provider. Raw log
payloads and ground-truth labels are omitted. Citation membership is validated;
the meaning of claims remains an analyst-review task.

A deterministic **local evidence brief** works without any model connection.
OpenRouter is also supported through the same Responses protocol:

```dotenv
IDENTITYSHIELD_AI_PROVIDER=openrouter
IDENTITYSHIELD_AI_MODEL=openai/gpt-6.1-sol
IDENTITYSHIELD_AI_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_API_KEY=your-working-openrouter-key
```

The `openai/` prefix is the model ID listed in OpenRouter's catalogue. Changing
the gateway does not make an invalid key valid; OpenRouter authentication must
succeed independently. This is remote inference, with the same evidence boundary.

For a genuinely local LLM, use a running Ollama server:

```dotenv
IDENTITYSHIELD_AI_PROVIDER=ollama
IDENTITYSHIELD_AI_MODEL=qwen3:8b
IDENTITYSHIELD_AI_BASE_URL=http://127.0.0.1:11434/v1
```

## Bring in real evidence

The **Datasets** page supports drag-and-drop imports and a documented OTRF sample
download. The Kaggle dialog lists the official HAI publisher's CSV files and can
use public access. Optional authentication uses `KAGGLE_API_TOKEN`, or the legacy
`KAGGLE_USERNAME` and `KAGGLE_KEY` pair.

```sh
# Exported Windows/Sysmon records
go run ./cmd/identityshield import -file events.jsonl -format windows-jsonl -source windows

# Stream a bounded slice from a large LANL authentication gzip
go run ./cmd/identityshield import -file auth.txt.gz -format lanl-auth -source lanl -max-events 20000

# Normalized industrial telemetry
go run ./cmd/identityshield import -file hai-slice.csv -format hai-csv -source hai
```

LANL time remains relative. Unmatched red-team labels do not certify normal
activity. OTRF/EVTX scenario annotations do not label every background event as
malicious. Training rejects insufficient verified normal data and incompatible
ICS schemas. Source cohorts can combine compatible imports without joining
unrelated identities or incident timelines.

The browser importer accepts up to **64 MiB** of uploaded and expanded payload
and defaults to **20,000 events** per import. Prepare bounded slices for large
corpora. Interactive analysis and training use at most the latest **200,000**
stored records. Native EVTX needs the Windows export script; Splunk indexes and OpTC
eCAR need a compatible normalized export.

See [dataset strategy](docs/DATASETS.md), [API](docs/API.md), and
[architecture](docs/ARCHITECTURE.md).

## Lab and simulator

See [lab setup](lab/README.md) for Windows/Hyper-V prerequisites and collection.
The setup scripts are supplied for execution in Windows; macOS app checks do
not execute or validate an AD forest deployment.

```sh
# Labelled fixture events to stdout
go run ./cmd/identityshield simulate -scenario identity-to-ot

# 100 L tank: five-second samples, manipulation begins after sample 20
go run ./cmd/identityshield tank -samples 60 -attack-after 20 -seed 42

# An explicit, source-bound synthetic permission snapshot
go run ./cmd/identityshield snapshot
```

The web replay produces telemetry through the actual ingestion and detection
pipeline. It executes no VM exploits or physical-controller commands.

## Verify

```sh
go test -race ./...
go vet ./...
npm ci
npx playwright install --only-shell chromium
npm run test:ui
```

Go checks cover permission precedence, cycles, source isolation, approval scope,
dataset labels, data leakage, protocol/citation validation, persistence, and API
controls. Browser checks exercise navigation, mobile layout, imports, replay,
training, local reports, export, and reviewer persistence.

## Deployment

Production: **https://identityshield.vercel.app**.

Vercel uses the native Go framework and `cmd/server` entrypoint, listens on its
assigned `PORT`, and stores evidence, manifests, policies, models, reviews, and
original payloads in durable Neon Postgres. Local SQLite remains available for
the desktop lab. Provider credentials are encrypted server-side environment
variables. The active provider is Agent Router, model `gpt-6.1-sol`, at
`https://agentrouter.org/v1`.

The Vercel project has Deployment Protection enabled. Sign in with the owning
Vercel account; the application also requires the workspace access token stored
as `IDENTITYSHIELD_ACCESS_TOKEN` in the owner's local `.env` file. The token is
not embedded in the browser or committed to GitHub.

See [Vercel operations](docs/VERCEL.md) for deployment and migration commands.

```sh
go build -o bin/identityshield ./cmd/identityshield
./bin/identityshield serve
```

The default listener is loopback. An explicit non-loopback listener requires
`IDENTITYSHIELD_ACCESS_TOKEN`; the browser prompts for this workspace token and
collectors send it as a bearer token. A Docker recipe and Compose configuration
are included. Docker requires that token in the environment and publishes its
host port only on loopback.

## Licence

Application code: [MIT](LICENSE). Third-party datasets retain their own terms.
Downloaded payloads, model state, and live credentials are not part of the repo.
