# AGENTS.md

## Dev workflow

Load the `dev-flow` skill before starting any task — a feature, a bugfix, or workflow setup — and follow its lane (unless the user chooses not to).

## What this is

`homeproxy` — an authenticated forward HTTP proxy for an iPhone's Wi-Fi proxy setting.
It accepts absolute-form HTTP requests and `CONNECT` tunnels, checks Basic credentials from
config, and forwards to a configurable upstream proxy (direct when the upstream is unset).

Stack: Go + miso (`github.com/curtisnewbie/miso`). Load the `miso` skill for framework questions.

## Build & Run

```bash
go build -o homeproxy .
./homeproxy configFile=conf.yml
go test ./...
```

## Agent skills

### Issue tracker

Issues and specs live as local markdown under `.scratch/`. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context: root `GLOSSARY.md` + `docs/adr/`. See `docs/agents/domain.md`.
