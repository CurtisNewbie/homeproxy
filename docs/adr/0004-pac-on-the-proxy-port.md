# The PAC file is served on the proxy port, and it falls back to DIRECT

iOS **Automatic** proxy mode takes a single URL: a Proxy Auto-Configuration script. The phone fetches
it and asks it, per request, whether to use a proxy. homeproxy generates one at `/proxy.pac` from
`homeproxy.pac.direct` and `homeproxy.pac.proxy`, so routing moves to the client and Manual's
"everything or nothing" stops being the only choice.

It is served on the **proxy port**. That port already binds `0.0.0.0`; the management port binds
`127.0.0.1` by miso's default, so serving there would mean publishing health and metrics to the LAN
before the phone could reach it. Origin-form `GET /proxy.pac` and proxied traffic cannot be confused:
a client that goes through the proxy sends absolute-form or `CONNECT`, never an origin-form path.

The PAC branch runs **before** the credential check, because Apple ignores `ProxyUsername` and
`ProxyPassword` when the proxy type is Automatic. A credential check on this path would therefore
break the client the file exists for, so the gate is an address: `homeproxy.pac.require-trusted-client`,
**on by default**, serves the file only to an address in `homeproxy.trusted-clients` and answers
`403` to anything else. With an empty trusted list the service still boots — it logs a warning and
serves the file to nobody. Turning the setting off makes the file public to anything that can reach
the proxy port, which reveals the proxy address and the direct host list and nothing else.

When the gate is off, untrusted traffic is deliberate, so the endpoint carries no rate limit: an
unauthenticated fetch costs one small string build, with no dial, DNS lookup or allocation beyond
that.

The emitted answer is `PROXY <proxy>; DIRECT`. The fallback keeps the phone working when homeproxy is
down, and it has a cost that is accepted here: a `403` from the private-network guard can be
followed by a direct connection from the phone, so the guard no longer bounds phone traffic.
Rejected: failing closed with `PROXY <proxy>` alone, which trades that convenience for a bound the
operator did not ask for.

The PAC direct list is separate from `homeproxy.bypass`. Bypass decides homeproxy's own egress, a
decision made at the server; the PAC list decides the client's, made on the phone. Reusing one list
would send `curtisnewbie.com` — reachable only from the home network — down the direct path from a
phone that is anywhere else.

The generated script uses plain string comparisons and no `shExpMatch`, `dnsResolve`, `isInNet`, or
lookup: PAC helper coverage differs between client implementations, and a name lookup would make the
answer depend on resolver state the operator cannot see.
