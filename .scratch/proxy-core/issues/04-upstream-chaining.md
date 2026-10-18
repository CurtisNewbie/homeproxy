# 04: Upstream chaining

**What to build:** Setting `homeproxy.upstream` sends every connection — tunnels and plain
requests alike — through that proxy, and clearing it returns to direct egress. Nothing else in
the system branches on the egress.

**Blocked by:** 02 (credential-gated CONNECT tunnel), 03 (plain-HTTP forwarding)

**Status:** done

- [x] with `homeproxy.upstream` set, a `CONNECT` tunnel reaches the target through the upstream: the fake upstream observes `CONNECT target:port`
- [x] with upstream set, an absolute-form request also reaches the target through the upstream
- [x] when `homeproxy.upstream.username`/`password` are set, the upstream receives `Proxy-Authorization`; when they are empty, it receives none
- [x] with upstream empty, the upstream observes nothing and the target is dialled directly
- [x] an upstream that refuses the `CONNECT` yields `502` to the client for that request only, and the next request still succeeds
- [x] an upstream that is unreachable yields `502` and is logged, without terminating the process
- [x] the egress choice is made in exactly one place: tunnels and forwarded requests use the same dialer
