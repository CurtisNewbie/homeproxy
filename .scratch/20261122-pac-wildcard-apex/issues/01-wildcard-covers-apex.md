# 01: A wildcard entry covers its own apex

**What to build:** An operator writes `*.example.com` once and the proxy treats `example.com` and
`api.example.com` the same way, in every host list — `homeproxy.pac.proxy-hosts`,
`homeproxy.pac.direct`, `homeproxy.bypass` — and the served PAC file answers the same verdict the
server would. An exact entry keeps matching that host alone. The property annotations that generate
`doc/config.md` state the new meaning.

**Blocked by:** None (can start immediately).

**Status:** done

- [x] `*.example.com` in `pac.proxy-hosts` makes the served PAC answer `PROXY <proxy>; DIRECT` for
      `example.com` and `api.example.com`, case-insensitively and with the port ignored
- [x] `*.example.com` in `pac.direct` answers `DIRECT` for both hosts in `proxy` mode
- [x] `*.example.com` in `homeproxy.bypass` exempts both `example.com` and `api.example.com` from
      the upstream and from the private-network guard
- [x] `example.com` still matches only `example.com`, never `api.example.com`, in every list
- [x] a list carrying both `example.com` and `*.example.com` answers exactly as either entry alone
- [x] `*.` in front of an IP literal still fails startup, naming the key and the entry
- [x] the property annotations for the three lists describe the wildcard-apex rule
- [x] tests that asserted the old strict rule now assert the new one, and the full suite is green