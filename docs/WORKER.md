# Go/OpenCode report worker

The hosted workspace queues fresh reports in Neon. A connected repo worker
claims each job over HTTPS and calls the pinned project-local OpenCode CLI.
The workspace checks evidence digests and citations before saving the report.

## Run from the project terminal

```sh
npm ci
go run ./cmd/underdog terminal
# Inside the terminal:
go run ./cmd/underdog worker
```

The ignored `.env` supplies the model key, `UNDERDOG_WORKER_TOKEN`, and optional
`UNDERDOG_WORKSPACE_URL`. Configure the same private worker token on Vercel with
`go run ./cmd/deploy -action worker-env`, then deploy. Production selects the
`worker` backend; the repo uses OpenCode to perform inference.

## Background worker on this Mac

The connected installation uses the login agent
`~/Library/LaunchAgents/com.fyield.underdog-worker.plist`. It starts
`bin/underdog worker` from the repo, restarts after an unexpected exit, and
starts at login. Logs are stored in the ignored `data/underdog-worker.log`.

```sh
launchctl print "gui/$(id -u)/com.fyield.underdog-worker"
launchctl kickstart -k "gui/$(id -u)/com.fyield.underdog-worker"
```

After updating the worker code, rebuild `bin/underdog` and restart the agent:

```sh
go build -trimpath -o bin/underdog ./cmd/underdog
launchctl kickstart -k "gui/$(id -u)/com.fyield.underdog-worker"
```

The Mac must be awake and online for fresh generation. The public interface
shows worker availability; persisted reports remain available when it is
offline. Closing a report dialog stops browser polling while its queued job
continues. Reopening the investigation displays its saved result.

To stop the login agent:

```sh
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.fyield.underdog-worker.plist"
```

Each report has an exclusive eight-minute lease. A crashed worker's lease can
be reclaimed; stale completions are rejected. Credentials and claim tokens are
never included in public job responses.
