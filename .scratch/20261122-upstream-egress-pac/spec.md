# homeproxy — upstream egress follows the PAC routing

Status: done

## Problem

`pac.proxy-hosts` (or `pac.direct`, depending on `pac.mode`) describes which targets belong
behind the proxy, but only the client reads it. The server sends every target that is not in
`homeproxy.bypass` to `homeproxy.upstream`. A client that ignores the PAC — manual proxy mode, a
cached file, an app with its own proxy setting — therefore reaches the internet through the
upstream even for hosts the PAC routes direct, and no config expresses the inverse ("upstream only
for the hosts the PAC proxies").

## Decision

Add `homeproxy.upstream.egress`, `all` (default) or `pac`. With `pac`, the upstream carries only
the targets the PAC routes through the proxy; the rest take the direct egress. `all` keeps today's
behaviour.

## Contract

- `homeproxy.upstream.egress`: `all` or `pac`, trimmed and lowercased; any other value fails startup
  and names both accepted values. Default `all`.
- The upstream settings live in one nested `upstream:` block: `homeproxy.upstream.address`,
  `.username`, `.password`, `.egress`. `homeproxy.upstream` remains as a deprecated alias for the
  address, used only when the nested address is empty.
- The PAC policy for a target is the same one the generated file applies: with `mode: direct`, the
  target is proxied when it matches `pac.proxy-hosts`; with `mode: proxy`, when it does not match
  `pac.direct`.
- Egress per target, decided once in `egressFor` and shared by tunnels and forwarded requests:

  | `bypass` match | `egress` | PAC policy | egress taken |
  |---|---|---|---|
  | yes | either | anything | direct, guard-exempt (unchanged) |
  | no | `all` | anything | upstream |
  | no | `pac` | proxied | upstream |
  | no | `pac` | direct | direct dial to the resolved, vetted addresses |

- The private-network guard is unchanged: it runs on every non-`bypass` target before the egress is
  chosen, so a PAC-direct private target is still refused unless it is in `homeproxy.bypass`.
- A PAC-direct target that does not resolve fails the request; there is no upstream to hand it to.
  A PAC-proxied target that does not resolve is still handed to the upstream, as today.
- Startup warns when an upstream is configured, `egress: pac` meets `mode: direct` and
  `pac.proxy-hosts` is empty: the upstream can never be used.
- `GET /proxy.pac` is unaffected — it is answered before any egress decision.

## Invariants

- With `egress: all`, no request changes egress: every target is handled exactly as it is today.
- `homeproxy.bypass` outranks both `egress` and the PAC policy; it is the only guard exemption.
- A direct target is always dialled at the addresses the guard vetted, never re-resolved.
- The setting never changes which addresses the client is told to use; it only bounds where the
  server sends what arrives.

## Acceptance criteria

- [ ] `egress: all` with an upstream behaves exactly as before: a non-bypass CONNECT reaches the
      upstream
- [ ] `egress: pac`, `mode: direct`: a listed host reaches the upstream; an unlisted host is dialled
      directly and the upstream sees no connection
- [ ] `egress: pac`, `mode: proxy`: a host in `pac.direct` is dialled directly; an unlisted host
      reaches the upstream
- [ ] a `bypass` match with `egress: pac` takes the direct egress for either PAC verdict
- [ ] a PAC-direct private target answers `403` and is not dialled; with a `bypass` entry it succeeds
- [ ] a PAC-direct target that fails to resolve fails the request and dials nothing
- [ ] `homeproxy.upstream.egress: mixed` fails startup, naming `all` and `pac`
- [ ] `egress: pac` with `mode: direct` and an empty `pac.proxy-hosts` logs the startup warning
- [ ] `doc/config.md` carries the new row, regenerated with `misoconfig -path doc/config.md`
- [ ] both sample configs show the key

## Testing Decisions

- `internal/config/config_test.go`: a validate table over `all`, `pac`, `""` (default) and an
  invalid value.
- `internal/proxy/proxy_test.go`: `startFakeUpstream` for "did the upstream see it" and
  `startCountingTarget` / `assertNoDial` for "was the target dialled"; one case per PAC-policy row,
  built from `testProxyConfig()` with `Bypass: nil` where the guard must refuse.
- `main_test.go`: one process test that the empty-list warning appears at startup.

## Required Skills

`dev-flow` (lane), `miso` (config property and defaults), `tdd`, `code-review`.

## Out of scope

- making `pac.direct`/`pac.proxy-hosts` imply a `bypass` entry
- per-target upstream selection beyond this binary choice
- any change to the PAC gate, the egress itself, or the upstream credentials