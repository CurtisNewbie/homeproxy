# 01: The guard checks what it can bind

**What to build:** the private-network guard stops resolving a target it cannot bind, and stops
resolving at all where the request is handed to the upstream. A private IP literal and a
name that can only mean something local are refused with no DNS query, always. A target the PAC
routes through the upstream is handed over untouched; every target homeproxy dials itself, and every
target under `egress: all`, is still resolved and still guarded. One new switch opens the proxy
completely and the resolver keeps a success for 120 s instead of 30 s.

**Blocked by:** None (can start immediately).

**Repo:** homeproxy

**Status:** done

- [x] a non-bypass `CONNECT` or absolute-form request for a private IP literal answers `403` with the guard on, and the fake upstream observes nothing
- [x] `localhost`, `nas.local`, `x.internal`, `y.lan`, `z.home.arpa` and `router` each answer `403` with the guard on, without a resolver query
- [x] `egress: pac` + a PAC-proxied target reaches the upstream with no lookup
- [x] `egress: pac` + a PAC-direct target is resolved, guarded and dialled at the vetted address
- [x] `egress: all` resolves every non-bypass target before contacting the upstream
- [x] a lookup failure on `egress: all` still hands the request to the upstream; on a direct egress it still answers `502`
- [x] `homeproxy.private-network-guard: false` lets a private literal and a local-only name through to the upstream, and startup logs the warning
- [x] the guard defaults to on when the key is absent
- [x] the resolver's success TTL is 120 s and the failure TTL is unchanged
- [x] `doc/config.md` carries the new key, regenerated with `misoconfig -path doc/config.md`
- [x] both sample configs show the key
- [x] the full suite passes
