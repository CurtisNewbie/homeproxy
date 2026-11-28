# homeproxy — the guard stops paying for lookups it cannot use

**Status:** done

## Problem Statement

A phone browsing through homeproxy feels slower than the same subscription on the laptop, and the
measurement agrees: the first connection to any host waits 90–275 ms before the client's TLS
handshake even starts, where clash answering on the same box answers a `CONNECT` in about 4 ms.

The cause is that homeproxy resolves every non-bypass target before it contacts the upstream, and
with `upstream.egress: all` that answer is then discarded — the upstream resolves the name again
itself. The guard's verdict on that path cannot bind: it is judging an address that another
resolver will replace a moment later. The cost is real, the protection is not.

Two smaller problems sit beside it. There is no way to turn the private-network guard off at all.
And an operator cannot see how much of a request's time went to resolution,
so the delay above is invisible in the logs. Finally, the resolver cache holds a success for only
30 s, so repeat visits re-pay the full lookup.

## Solution

Split the guard into the checks that can bind and the lookup that only sometimes can:

- A private IP literal and a name that can only mean something local are refused without any DNS
  query, always, whatever the egress.
- The DNS lookup runs only where homeproxy dials the target itself, plus the `egress: all` case the
  operator asked to keep checked. A target the PAC hands to the upstream is not looked up at all.
- One switch, `homeproxy.private-network-guard`, turns the guard off entirely for an operator who
  wants an open proxy; empty by default so the guard stays on.
- The resolver's success cache grows from 30 s to 120 s.
- Both request log lines report the resolution time, or that no lookup ran.

## Repos

- homeproxy — base `main`

## User Stories

1. As the phone's user, I want the first connection to a new host to reach clash immediately, so that
   page loads stop paying a lookup the proxy cannot use.
2. As the operator, I want the private-network guard to keep refusing a request for my router's
   address, so that a leaked credential still cannot use the proxy as a LAN doorway.
3. As the operator, I want a request for `nas.local` or `router` refused without a resolver round
   trip, so that local-only names are handled the same way on every platform.
4. As the operator running `egress: all`, I want every target still resolved, so that the guard I
   configured stays as strict as it is today.
5. As the operator running `egress: pac`, I want a host I deliberately listed for the proxy to be
   handed over untouched, so that the list is the only gate on it.
6. As the operator, I want a single switch that opens the proxy completely, so that I can test
   without maintaining a bypass list that does not do what it looks like.
7. As the operator, I want that switch to default to on, so that an upgrade never silently opens the
   proxy.
8. As the operator, I want the guard's refusals and the guard being off to appear in the request
   log, so that I can tell a policy decision from a network failure.
9. As the operator debugging latency, I want each request line to report how long resolution took or
   that it was skipped, so that the next slow report is diagnosable from logs alone.
10. As the operator, I want a repeat visit within two minutes to skip the lookup, so that browsing
    the same site does not pay DNS on every connection.
11. As the phone's user, I want every request the guard permits to take exactly the egress it takes
    today, so that this change alters latency and the off-switch, nothing else.

## Implementation Decisions

**Check order.** For a non-bypass target, the guard decides in this order, and each step stops the
request before any dial or upstream contact:

1. Guard disabled → no check at all; the egress proceeds as configured.
2. Target host parses as an IP literal and the address is non-public → refuse.
3. Target host is a name that can only mean something local → refuse.
4. The target needs a DNS lookup (see the egress table) → resolve, refuse if any answer is
   non-public, otherwise continue.

**Local-only names.** A fixed list, matched case-insensitively on the host with the port and a
trailing dot removed: the bare forms and subdomains of `.localhost`, `.local`, `.internal`, `.lan`,
`.home.arpa`, and any single-label name (`nas`, `router`) — a single-label name has no public
meaning. The list is closed; no config extends it.

**When the lookup runs.** "Upstream-carried by the PAC" means an upstream is configured,
`upstream.egress` is `pac`, and the PAC routes this target through the proxy.

| upstream configured | `egress` | PAC routes the target | lookup |
|---|---|---|---|
| no | — | — | yes, then direct dial |
| yes | `all` | n/a (not consulted) | yes |
| yes | `pac` | through the proxy | **no** |
| yes | `pac` | direct | yes, then direct dial |

A target the PAC hands to the upstream therefore loses the resolved-address verdict and keeps the
literal and local-name checks. This is the trade the operator accepted: on that path the verdict
could not bind, because the upstream resolves the name again. `bypass` still outranks this table
and stays guard-exempt and direct.

**Guard switch.** `homeproxy.private-network-guard`, boolean, default `true`. `false` removes every
check in the list above — no lookup, no literal refusal, no local-name refusal — and changes no
egress. Startup logs a warning when it is `false`, naming what is now reachable.

**Resolver cache.** Success TTL 30 s → 120 s. Failure TTL stays 5 s, and the entry cap stays as it
is. The longer TTL is safe for the direct path because a stale address fails the dial rather than
reaching somewhere else; no retry is added.

**Resolution left as it is.** `dial-timeout-seconds` remains the only budget, and it still covers the
lookup on every path that performs one. No second, shorter budget is introduced.

**Resolution in the log.** Both request lines gain one field beside the existing duration:
`resolve=<Go duration>` when a lookup ran, `resolve=skipped` when the egress table says no lookup
runs, and `resolve=failed` is not a separate value — a failed lookup reports its elapsed time and
the existing outcome already says `lookup-failed` / the request was handed to the upstream. No new
metric is added.

**Documentation.** The config table gains the new key and the meaning of the egress interaction;
both sample configs show the key commented, with the guard on.

**Where the decision lives.** The egress decision, the guard verdict and the resolve timing are all
produced by one decision point per request, before the transport is used, and handed to the
transport through the request context. The log line reads them from there; no handler re-derives an
egress.

## Contracts

### Data

N/A — no store, no schema, no persisted state. The resolver cache is in-process and bounded by an
entry cap; its entries have no identity beyond the host string.

### Interfaces

No HTTP surface changes: the proxy port, the PAC file, auth and the status codes a client sees stay
as they are. The only new client-visible behaviour is a `403` where a local-only name used to
produce an upstream failure or a lookup-dependent verdict. The request log line gains the
`resolve=` field described above; that line is an operator interface, so the field name and its
three shapes (`<duration>`, `skipped`) are contract.

### Config

| key | type | domain | default | owner | effect |
|---|---|---|---|---|---|
| `homeproxy.private-network-guard` | bool | — | `true` | proxy | `false` disables every guard check; no egress change; startup warns |
| `homeproxy.upstream.egress` | string | `all`, `pac` | `all` | proxy | unchanged, and now also selects whether a PAC-proxied target is looked up |
| `homeproxy.bypass` | host list | exact or `*.suffix` | empty | proxy | unchanged |
| `homeproxy.dial-timeout-seconds` | int | > 0 | `10` | proxy | unchanged; still the lookup budget wherever a lookup runs |

The resolver TTL is not config: it is a constant that becomes 120 s.

## Invariants

- A `bypass` match is guard-exempt and takes the direct egress; nothing in this change alters that.
- A private IP literal and a local-only name are never resolved, on any egress, while the guard is on.
- While the guard is on, a target the PAC hands to the upstream produces no DNS query from homeproxy.
- With `egress: all` and the guard on, every non-bypass target that is not refused as a literal or a
  local-only name is resolved before the upstream is contacted, as it is today.
- A guard refusal answers `403` before any dial and before the upstream sees the request.
- A direct egress still dials the vetted addresses, never the hostname, so a second DNS answer cannot
  redirect an approved connection.
- Turning the guard off changes no egress decision and adds no lookup.
- Every request the guard permits reaches the egress it reaches today.

## States and failure

Per request the guard ends in exactly one of: **off** (no checks), **permitted** (a lookup ran, or
none was needed), **refused** (`403`, outcome `forbidden`), or **lookup-failed** (direct egress:
`502`, outage logged; upstream egress: handed over, failure logged). Dial and upstream-CONNECT
failures keep their current `502` outcomes. There is no retry and no partial success: the states are
terminal for the request.

A PAC-proxied target has no lookup-failed state, because no lookup runs for it.

## Boundaries

- **Upstream (clash or another HTTP proxy).** Homeproxy dials it and writes one `CONNECT`; the
  upstream resolves the target name itself and owns its own DNS, rules and node selection. Homeproxy
  neither sees nor retries that resolution. When the upstream is down or hangs, the failure surfaces
  as the existing dial/`502` path, bounded by `dial-timeout-seconds`.
- **Client PAC.** The file is advice, not enforcement: a client may ignore it or cache it, and a
  `PROXY x; DIRECT` entry may fall back to direct without touching homeproxy. Homeproxy never rejects
  a request because the PAC would have routed it direct.
- **System resolver.** Consulted only where the egress table says a lookup runs; its answers are
  cached in-process for 120 s and are the addresses a direct dial pins to.

## Testing Decisions

Tests assert behaviour through the proxy's HTTP surface — `CONNECT` and absolute-form requests
against the existing fake upstream and counting target — never against the resolver directly. Prior
art: the egress tests already built on the shared test config, the fake upstream ("did the upstream
see it"), the counting target with `assertNoDial`, and the log buffer with its wait helper.

Three seams:

1. **The proxy's HTTP surface.** A private IP literal and each local-only name shape answer `403`
   and the fake upstream observes nothing; a public host under each egress mode reaches the upstream
   or the target as the table says; a PAC-proxied private-address host reaches the upstream (the
   accepted trade); the guard switch off makes the same requests succeed.
2. **The request log line.** A PAC-proxied target logs `resolve=skipped`; an `egress: all` target logs
   `resolve=` with a duration; a guard refusal and a guard-off request are distinguishable in the
   line's existing outcome/egress fields.
3. **Config loading.** The new boolean defaults to `true` and accepts `false`.

The resolver cache's 120 s TTL is not asserted through time; a direct-dial test asserts that two
requests to one host inside the TTL dial the same vetted address, which is the behaviour the TTL
changes.

## Required Skills

`miso` — the new boolean property, its default and the startup warning (`configuration`,
`bootstrap`). `tdd` and `code-review` are already required by the repo.

## Acceptance Criteria

- [x] a non-bypass `CONNECT` or absolute-form request for a private IP literal answers `403` with the
      guard on, and the fake upstream observes nothing
- [x] `localhost`, `nas.local`, `x.internal`, `y.lan`, `z.home.arpa` and `router` each answer `403`
      with the guard on, without a resolver query
- [x] `egress: pac` + a PAC-proxied target reaches the upstream with no lookup, and the log line
      carries `resolve=skipped`
- [x] `egress: pac` + a PAC-direct target is resolved, guarded and dialled at the vetted address
- [x] `egress: all` resolves every non-bypass target before contacting the upstream, and the log line
      carries a `resolve=` duration
- [x] a lookup failure on `egress: all` still hands the request to the upstream; on a direct egress it
      still answers `502`
- [x] `homeproxy.private-network-guard: false` lets a private literal and a local-only name through
      to the upstream, and startup logs the warning
- [x] the guard defaults to on when the key is absent
- [x] the resolver's success TTL is 120 s and the failure TTL is unchanged
- [x] `doc/config.md` carries the new key, regenerated with `misoconfig -path doc/config.md`
- [x] both sample configs show the key
- [x] the full suite passes

## Out of Scope

- rejecting a request because the PAC routes its host direct (PAC stays advice)
- a separate, shorter lookup budget
- stale-while-revalidate or singleflight in the resolver
- `MaxIdleConnsPerHost` and any other transport tuning
- extending the local-only name list through configuration

## Further Notes

The measurements that opened this change: on the LAN, `CONNECT` setup through clash on the same box
was ~4 ms for both warm and cold hosts; through homeproxy it was ~5 ms warm and 91–275 ms for a cold
foreign host, tracking that host's DNS cost. Throughput was at parity with clash on the same box, so
bandwidth was never the problem.
