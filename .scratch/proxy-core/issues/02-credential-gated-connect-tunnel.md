# 02: Credential-gated CONNECT tunnel, direct egress

**What to build:** A client that supplies a valid credential gets a working `CONNECT` tunnel to
the target and can carry TLS through it; a client with no credential or a bad one gets the same
challenge, and no tunnel is opened. Requires no upstream: egress is direct.

**Blocked by:** 01 (service skeleton, config, management surface)

**Status:** ready-for-agent

- [ ] a `CONNECT` without `Proxy-Authorization` receives `407` with `Proxy-Authenticate`, and no upstream or target connection is dialled
- [ ] a `CONNECT` with an unknown name and a `CONNECT` with a wrong secret produce identical responses
- [ ] a `CONNECT` with a valid credential receives `200 Connection Established`
- [ ] bytes flow in both directions through the tunnel to a local TLS server, including a request/response round trip
- [ ] preemptive `Proxy-Authorization` (no prior 407) is accepted, as a non-iOS client sends it
- [ ] half-close is preserved: when the client finishes its request the response still arrives in full
- [ ] the tunnel closes both sides when either side ends, and the listener keeps accepting afterwards
