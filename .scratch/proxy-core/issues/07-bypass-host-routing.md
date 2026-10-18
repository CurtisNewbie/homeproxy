# 07: Bypass host routing

**What to build:** A configured list of hosts reaches the target directly instead of through the
upstream, so reaching your own services does not depend on the upstream being up or unmetered.

**Blocked by:** 04 (upstream chaining)

**Status:** done

- [x] an exact host in `homeproxy.bypass` is dialled directly while an upstream is configured
- [x] `*.suffix` matches subdomains but not the bare suffix itself; a bare suffix must be listed separately
- [x] matching is case-insensitive and ignores the port
- [x] a host not matching any entry still goes through the upstream
- [x] a bypass host that resolves to a private address is dialled and allowed
- [x] the log line names the chosen egress for both matched and unmatched requests
- [x] `homeproxy.bypass` appears in `doc/config.md`
