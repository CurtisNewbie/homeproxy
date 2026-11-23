# homeproxy

A small standalone forward HTTP proxy that gives a phone a stable, credential-gated way to reach
a chosen egress.

## Language

### Proxy access

**Credential**:
A name and secret pair that authorizes a client to use the proxy. Each device gets its own.
_Avoid_: user, account, login

**Trusted client**:
An address — a single IPv4/IPv6 address or a CIDR — whose requests use the proxy without a
credential. The private-network guard still applies to its targets.
_Avoid_: whitelist, allowlist, IP auth

**Egress**:
Where traffic goes to reach the internet — through the upstream when one is configured, directly
otherwise. One setting decides it for every connection.
_Avoid_: route, exit node, egress mode

**Upstream**:
The HTTP proxy that homeproxy hands connections to when an egress other than direct is
configured.
_Avoid_: parent proxy, chained proxy

**Managed clash**:
The clash-compatible instance whose controller homeproxy reaches to keep one group selection in
place. It need not be homeproxy's upstream.
_Avoid_: managed proxy, clash admin, upstream manager

**Preferred proxy**:
The proxy homeproxy keeps selected in the managed clash's selector — at startup, and again whenever a
drift check finds it changed. When it is a `URLTest` or `Fallback` group, clash picks the node inside
it; homeproxy never picks a node.
_Avoid_: target group, region, node, member

**Host list**:
A list of target hosts — `homeproxy.bypass` and the two PAC lists. An entry is an exact host, which
covers that host alone, or a `*.suffix`, which covers the suffix host and every host under it.
_Avoid_: route list, whitelist, domain list

**Bypass**:
A host list whose entries use the direct egress and are exempt from the private-network guard.
_Avoid_: route, whitelist, no-proxy list

**PAC file**:
The Proxy Auto-Configuration script served at `/proxy.pac`, which a client fetches to choose, per
request, between homeproxy and a direct connection. Its entries are the list the active
`homeproxy.pac.mode` consults — `proxy-hosts` in `direct` mode, `direct` in `proxy` mode — not the
bypass list.
_Avoid_: proxy URL, auto-proxy config, wpad.dat

**Private-network guard**:
The always-on check that refuses a non-bypass host resolving to a non-public address, before any
connection is dialled.
_Avoid_: private-address guard, SSRF filter

**Tunnel**:
The bidirectional byte stream a `CONNECT` request opens between client and target.
_Avoid_: session, connection

### Operating the proxy

**Management surface**:
The local HTTP port that serves health and metrics, separate from the proxy port.
_Avoid_: admin API, control plane
