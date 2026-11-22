# homeproxy — a wildcard host entry covers its own apex

Status: done

## Problem

A `*.suffix` entry matches subdomains only. An operator who wants a domain and everything under it
— `youtube.com` and every `*.youtube.com` host — must write the pair twice: `youtube.com` and
`*.youtube.com`. Two entries that read as one intent, repeated in every list that must carry it
(`homeproxy.pac.proxy-hosts`, `homeproxy.pac.direct`, `homeproxy.bypass`), and one of them is easy
to forget, which silently narrows the rule.

## Decision

A `*.suffix` entry in any host list covers the bare suffix host as well as its subdomains:
`*.youtube.com` matches `youtube.com` and `api.youtube.com`. An exact entry keeps its meaning and
matches that host alone — the implication runs one way. The rule is the same in the served PAC body,
so the client and the server never disagree about what an entry covers.

The trade: nothing expresses "subdomains only, leave the apex out" once this lands. Accepted — that
distinction is what forced the duplicate entries, and no operator in the sample configs relies on it.

This rewrites shipped behaviour: `.scratch/20261122-pac-mode/spec.md` states `*.suffix` matches
subdomains only, and its acceptance criteria assert it. That spec stays as reviewed; this one
supersedes the rule.

## Contract

- A host list is `homeproxy.bypass`, `homeproxy.pac.direct` or `homeproxy.pac.proxy-hosts`. All
  three share one matcher and adopt the rule together — no list keeps the old, strict meaning.
- Entry `*.suffix` matches `suffix` and any host ending in `.suffix`. Matching stays
  case-insensitive and ignores the port and a trailing dot, as today.
- Entry `host` matches `host` only: `youtube.com` does not match `api.youtube.com`.
- A list carrying both `youtube.com` and `*.youtube.com` stays valid and answers the same verdict
  for the apex as before; the duplicate is redundant, not an error.
- Validation is unchanged: the two PAC lists keep their checks (`HostOnly` normalization, optional
  `*.`, no `*.` in front of an IP literal, no zoned IP) and `homeproxy.bypass` keeps the absence of
  any check it has today (see Out of Scope).
- The generated PAC body applies the same two rules per entry — apex and subdomains for a wildcard,
  one comparison worth of work per entry, still one verdict per host.
- Documentation states the new meaning everywhere the old one is written: the property
  descriptions that generate `doc/config.md`, the README's PAC and bypass sections, the sample
  config comments, and the glossary's host-list term.

## Invariants

- The server's matcher and the generated PAC body give the same answer for every host a client can
  query: the body normalizes what a PAC `host` argument can carry — case, an IPv6 bracket pair, a
  trailing dot — and the server's wider authority parsing adds only forms a client never sends.
- An exact entry never matches a host it does not name, and never a subdomain of the named host.
- Everything else is unchanged: the mode's one active list, the `; DIRECT` fallback, the
  private-network guard and its `bypass` exemption, PAC auth and caching, the `400` on an unusable
  request `Host`.
- The PAC body stays a flat sequence of comparisons over normalized values; nothing is resolved or
  expanded at serve time.

## Acceptance criteria

- [x] `*.example.com` in `pac.proxy-hosts` makes the served PAC answer `PROXY` for both
      `example.com` and `api.example.com`, case-insensitively
- [x] `*.example.com` in `pac.direct` answers `DIRECT` for both hosts in `proxy` mode
- [x] `*.example.com` in `homeproxy.bypass` exempts both `example.com` and `api.example.com` from
      the upstream and from the private-network guard
- [x] `example.com` still matches only `example.com`, never `api.example.com`, in every list
- [x] a host listed twice (`example.com` plus `*.example.com`) behaves exactly as either entry alone
- [x] the PAC lists still reject `*.` in front of an IP literal at startup, naming the key and the
      entry
- [x] `doc/config.md`, README, GLOSSARY and the sample configs describe the new meaning; `doc/config.md`
      is regenerated from the property annotations
- [x] the full suite is green, with the tests that asserted the old strict rule updated to the new one

## Testing Decisions

No new seam. Existing seams carry the whole change:

- `internal/proxy` PAC seam — the handler from `New(cfg)` on an ephemeral port answering an
  origin-form `GET /proxy.pac`, asserted on the body text — covers the wildcard-apex and
  exact-only rules per mode, and the duplicate-entry case.
- `internal/proxy` request seam — a proxied request against a live upstream — covers the `bypass`
  rule's effect on egress and on the private-network guard.
- `internal/config` validation table — covers that an invalid wildcard entry still fails startup.

Tests assert behaviour (what a host is answered, where a request goes), never the emitted body's
internal shape beyond the verdicts it returns.

## Required Skills

`dev-flow` (lane), `miso` (config property annotations and `doc/config.md` regeneration), `tdd`,
`code-review`.

## Out of Scope

- exact entries gaining subdomain matching
- a syntax for "subdomains only" — that meaning is deliberately dropped
- multi-level or mid-label wildcards (`api.*.example.com`), and any new syntax at all
- changing which list a mode consults, or the private-network guard's rules
- the upstream-egress policy, which reuses the same matcher and inherits the rule without this
  spec changing it
- adding load-time validation to `homeproxy.bypass`: it is the one host list the config never
  validates, so a `*.` in front of an IP there is accepted and matches today — a pre-existing gap
  that this change does not widen and does not close

## Further Notes

- Record the rule and its trade in `docs/adr/0006-wildcard-covers-apex.md`: a `*.suffix` entry
  covering the apex surprises a reader, and the loss of the strict form is the trade that buys it.
  The glossary's host-list term is updated in the same change.
- `homeproxy.bypass`'s documented examples (`*.corp.internal`, `*.youtube.com`) gain their apexes
  under this rule; both are wanted, so the sample configs need no structural edit.