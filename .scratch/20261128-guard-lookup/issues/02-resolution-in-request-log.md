# 02: Resolution time in the request log

**What to build:** both request log lines report how long the guard's resolution took, or that no
lookup ran, so a slow report is diagnosable from the log alone. A target the PAC hands to the
upstream logs `resolve=skipped`; a target resolved under `egress: all` or a direct egress logs
`resolve=` with its duration; a guard refusal and a guard-off request stay distinguishable through
the fields the line already carries. No new metric.

**Blocked by:** 01 (the egress decision must carry the resolve timing and the skipped state).

**Repo:** homeproxy

**Status:** ready-for-agent

- [x] a PAC-proxied target logs `resolve=skipped`
- [x] an `egress: all` target logs `resolve=` with a duration
- [x] a direct-egress target logs `resolve=` with a duration
- [x] a private-literal and a local-only refusal each log with the guard-off and the dial-failure cases still distinguishable
- [x] no new metric is registered
- [x] the full suite passes
