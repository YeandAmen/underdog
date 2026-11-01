# Vercel operations

Production: https://identityshield.vercel.app

The native Go runtime builds `cmd/server`, serves the embedded interface, and
listens on `PORT`. Production uses Neon Postgres through `DATABASE_URL`.
Local SQLite data remains under `data/`; it is not bundled into the deployment.
Neon stores the normalized events, manifests, policy snapshots, model trees,
review notes, and original import payloads. Large originals can be retained as
ordered binary chunks without sending a huge single SQL parameter.

## Provider configuration

Production is configured for:

```dotenv
IDENTITYSHIELD_AI_PROVIDER=agentrouter
IDENTITYSHIELD_AI_MODEL=gpt-6.1-sol
IDENTITYSHIELD_AI_BASE_URL=https://agentrouter.org/v1
AGENT_ROUTER_API_KEY=<server-side credential>
KAGGLE_API_TOKEN=<server-side credential>
DATABASE_URL=<Neon integration connection>
IDENTITYSHIELD_ACCESS_TOKEN=<owner workspace token>
```

`cmd/deploy -action env` reads local ignored credentials and sends them to Vercel
without printing their values. Vercel's native Neon integration provisions the
database credentials. `.env`, `.env.local`, and `.vercel` metadata are ignored.

## Commands

```sh
npx vercel link --project identityshield --yes
npx vercel install neon --non-interactive
go run ./cmd/deploy -action verify
go run ./cmd/deploy -action migrate
go run ./cmd/deploy -action payloads
go run ./cmd/deploy -action env
npx vercel --prod --yes
go run ./cmd/deploy -action check-web
```

The HTTPS SQL migration path can run in development environments that restrict
outbound PostgreSQL TCP connections. The deployed Go server uses native Postgres
connections. Migration is idempotent by event ID and original-payload hash.
Whole-run/day model boundaries and existing reviewer labels remain intact.

## Access and verification

Vercel Deployment Protection requires the owning account. CLI verification uses
`vercel curl`, which obtains the project's bypass token. Application API access
also requires the owner's workspace bearer token. `check-web` reads the token
locally and prints only counts and provider/model status.

An available deployment does not establish that the upstream AI credential is
valid. Agent Router errors are surfaced by the app. Local evidence briefs and
Go model inference do not require a live language-model connection.
