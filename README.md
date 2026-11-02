# Underdog

**Helping office teams understand access and cyber threats.**

[Open Underdog](https://underdog-fyield1.vercel.app)

## Why i built it

I built Sinnogram to make organising locations in Abuja easier. With Underdog,
i brought that same approach to office cybersecurity.

Office teams need to know who has access, what looks suspicious, and what needs
attention. That information is often scattered across accounts, logs and alerts.

Underdog brings it together. I built it to help teams spot access problems,
understand possible threats, and decide what to review next.

## What i built

- **One overview** for office accounts, alerts and access issues.
- **Access checks** that show who can reach important systems and where access
  does not match a person's role.
- **Threat checks** for unusual sign-ins and suspicious activity.
- **Behaviour models** that learn from normal activity and highlight changes.
- **Investigations** that keep an alert and its supporting records together.
- **AI reports** that explain the findings and link back to the evidence.
- **Team reviews** for saving decisions, adding notes and downloading reports.
- **Log imports** so teams can review their own activity records.
- **A practice lab** for exploring threats with sample data.
- **A Go terminal with OpenCode** built into the project for AI work.
- **A responsive workspace** with search, live updates, and light and dark themes.

Try the demo with sample data, or import your own logs.

## Run locally

Requires Go 1.26 or newer.

```sh
go run ./cmd/underdog serve
```

Open [localhost:8787](http://127.0.0.1:8787).

For the project terminal, install OpenCode with Node.js first:

```sh
npm ci
go run ./cmd/underdog terminal
```

## Setup guides

- [Model and deployment setup](docs/VERCEL.md)
- [AI worker setup](docs/WORKER.md)
- [Importing data](docs/DATASETS.md)
- [Practice lab](lab/README.md)

## Licence

[MIT](LICENSE). Imported datasets keep their own licences.
