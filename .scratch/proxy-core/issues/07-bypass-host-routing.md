# 07: Bypass host routing

**What to build:** A configured list of hosts reaches the target directly instead of through the
upstream, so reaching your own services does not depend on the upstream being up or unmetered.

**Blocked by:** 04 (upstream chaining)

**Status:** ready-for-agent

- [ ] an exact host in `homeproxy.bypass` is dialled directly while an upstream is configured
- [ ] `*.suffix` matches subdomains but not the bare suffix itself; a bare suffix must be listed separately
- [ ] matching is case-insensitive and ignores the port
- [ ] a host not matching any entry still goes through the upstream
- [ ] a bypass host that resolves to a private address is dialled and allowed
- [ ] the log line names the chosen egress for both matched and unmatched requests
- [ ] `homeproxy.bypass` appears in `doc/config.md`
