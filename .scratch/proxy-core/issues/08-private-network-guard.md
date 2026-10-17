# 08: Private-network guard

**What to build:** The proxy refuses to reach loopback, private, link-local, CGNAT, metadata or
multicast addresses unless the host is explicitly listed as yours, so a leaked credential cannot
turn the proxy into a doorway to the LAN.

**Blocked by:** 07 (bypass host routing)

**Status:** ready-for-agent

- [ ] a non-bypass host resolving to a loopback, RFC1918, link-local, CGNAT or multicast address receives `403` and nothing is dialled
- [ ] the same rule applies to `CONNECT` and to absolute-form requests
- [ ] the denial happens before the request is handed to the upstream: the fake upstream observes nothing
- [ ] a host listed in `homeproxy.bypass` is exempt and is dialled despite resolving private
- [ ] a public host is unaffected and still follows the configured egress
- [ ] resolution results are cached briefly, so repeated requests to one host do not repeat the lookup
- [ ] when resolution fails, the request is handed to the upstream if one is configured and answered `502` otherwise, and the failure is logged
- [ ] the log line distinguishes a policy denial from a dial failure
- [ ] the guard's configuration surface, if any, appears in `doc/config.md`
