# homeproxy — PAC routing mode

Status: done

## Problem

The generated PAC proxies every host by default: it answers `PROXY <proxy>; DIRECT` for everything
except `homeproxy.pac.direct`, which is an exemption list. An operator who wants the opposite — only
a few hosts through homeproxy, everything else direct — has no way to say it. Listing the internet
as exemptions is not a workable config.

## Decision

Add `homeproxy.pac.mode`, `proxy` or `direct`, default **`direct`**. In `direct` mode every host
answers `DIRECT` except the entries in the new `homeproxy.pac.proxy-hosts`, which answer
`PROXY <proxy>; DIRECT`. In `proxy` mode the file works as it does today: every host answers
`PROXY <proxy>; DIRECT` except the entries in `homeproxy.pac.direct`, which answer `DIRECT`.

Exactly one exception list belongs to each mode. A list with entries that the active mode never
consults logs one startup warning and does not block startup, so flipping the mode does not force an
edit of both lists.

## Contract

- Setting `homeproxy.pac.mode`: `direct` (default) or `proxy`, case-insensitive after trimming. Any
  other value fails startup, naming the key and the value.
- Setting `homeproxy.pac.proxy-hosts`: string list, default empty. Hosts that use the proxy in
  `direct` mode — an exact host or a `*.suffix`. Validated exactly as `homeproxy.pac.direct` is
  (`HostOnly` normalization, optional `*.`, no `*.` in front of an IP literal, no zoned IP).
- Setting `homeproxy.pac.direct`: unchanged; consulted only in `proxy` mode.
- Body: `FindProxyForURL(url, host)` answers `DIRECT` or `PROXY <proxy>; DIRECT` per the mode and
  its list. A proxied answer keeps the `; DIRECT` fallback.
- Startup: a `proxy-hosts` entry in `proxy` mode, or a `direct` entry in `direct` mode, logs one
  warning naming the key and the active mode. Startup continues.
- Everything else is unchanged: origin-form only, answered before the credential check, the
  `require-trusted-client` gate, `pac.proxy` normalization, the `400` on an unusable request `Host`.

## Invariants

- Exactly one exception list is consulted in a given mode; the other never affects the answer.
- An empty exception list still produces a valid file: every host gets the mode's default answer.
- A host in both lists is answered by the list the active mode consults.
- Existing keys keep their meaning in the mode that consults them.

## Acceptance criteria

- [x] `pac.mode` defaults to `direct`; an unlisted host answers `DIRECT`
- [x] in `direct` mode a `proxy-hosts` entry answers `PROXY <proxy>; DIRECT`, and `*.suffix` matches
      subdomains only, case-insensitively
- [x] in `proxy` mode an unlisted host answers `PROXY <proxy>; DIRECT` and a `pac.direct` entry
      answers `DIRECT`
- [x] an inert list logs exactly one warning at startup and startup succeeds
- [x] an invalid `pac.mode` value fails startup, naming the key and the value
- [x] `proxy-hosts` entries are validated exactly like `pac.direct` entries
- [x] a PAC still serves `200` with the configured mode's answers, unchanged in every other respect
- [x] `doc/config.md` documents every key through its `misoconfig-prop` annotation

## Testing Decisions

The existing seam holds: `New(cfg)` returns the handler, tests listen on an ephemeral TCP port and
send an origin-form `GET /proxy.pac`, asserting the body as text. Config validation and the inert-list
warning are tested through `internal/config` and `main_test.go` respectively, as the merged feature
already does.

## Required Skills

`dev-flow` (lane), `miso` (config properties and defaults), `tdd`, `code-review`.

## Out of scope

- per-URL or per-port rules; host matching only
- removing or renaming `homeproxy.pac.direct`
- any other PAC behaviour