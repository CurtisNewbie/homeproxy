# 05: Operator visibility

**What to build:** The operator can see who used the proxy, where traffic went, how much moved and
how it ended, without any credential reaching a log file or a metric.

**Blocked by:** 02 (credential-gated CONNECT tunnel, direct egress)

**Status:** done

- [x] each finished tunnel or forwarded request logs one line with credential name, target, bytes up, bytes down, duration and outcome
- [x] an authentication failure logs the remote address and attempted name only
- [x] no log line ever contains a secret or a `Proxy-Authorization` value
- [x] `/metrics` exposes byte counters, an auth-failure counter, a requests counter, an active-tunnels gauge and a dial-duration histogram
- [x] the active-tunnels gauge rises while a tunnel is open and returns to its previous value after it closes
- [x] a dial failure is counted and logged with its target and error
