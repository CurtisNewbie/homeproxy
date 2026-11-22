# AGENTS.md

## Dev workflow

Load the `dev-flow` skill before starting any task — a feature, a bugfix, or workflow setup — and follow its lane (unless the user chooses not to).

## What this is

`homeproxy` — an authenticated forward HTTP proxy for an iPhone's Wi-Fi proxy setting.
It accepts absolute-form HTTP requests and `CONNECT` tunnels, authorizes a client by Basic
credential or by trusted address, and forwards to a configurable upstream proxy (direct when the
upstream is unset). It serves a generated PAC file at origin-form `GET /proxy.pac` on the proxy port,
so a client can route per host.

Stack: Go + miso (`github.com/curtisnewbie/miso`). Load the `miso` skill for framework questions.

## Build & Run

```bash
go build -o homeproxy .
./homeproxy configFile=conf.yml
go test ./...
```

## Agent skills

Two skills are mandatory. Load them before the first action of every task; they are not optional
reading:

- `dev-flow` — decides the lane and the record. No task starts without it.
- `miso` — the framework contract. Load it before reading or changing configuration, bootstrap,
  middleware, or logging code.

### Issue tracker

Issues and specs live as local markdown under `.scratch/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` + `docs/adr/`. See `docs/agents/domain.md`.

### Code review

Read before writing and when reviewing code. See `docs/agents/code-review.md`.
