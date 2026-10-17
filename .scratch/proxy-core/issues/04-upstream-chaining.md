# 04: Upstream chaining

**What to build:** Setting `homeproxy.upstream` sends every connection — tunnels and plain
requests alike — through that proxy, and clearing it returns to direct egress. Nothing else in
the system branches on the egress.

**Blocked by:** 02 (credential-gated CONNECT tunnel), 03 (plain-HTTP forwarding)

**Status:** ready-for-agent

- [ ] with `homeproxy.upstream` set, a `CONNECT` tunnel reaches the target through the upstream: the fake upstream observes `CONNECT target:port`
- [ ] with upstream set, an absolute-form request also reaches the target through the upstream
- [ ] when `homeproxy.upstream.username`/`password` are set, the upstream receives `Proxy-Authorization`; when they are empty, it receives none
- [ ] with upstream empty, the upstream observes nothing and the target is dialled directly
- [ ] an upstream that refuses the `CONNECT` yields `502` to the client for that request only, and the next request still succeeds
- [ ] an upstream that is unreachable yields `502` and is logged, without terminating the process
- [ ] the egress choice is made in exactly one place: tunnels and forwarded requests use the same dialer
