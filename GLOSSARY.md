# homeproxy

A small standalone forward HTTP proxy that gives a phone a stable, credential-gated way to reach
a chosen egress.

## Language

### Proxy access

**Credential**:
A name and secret pair that authorizes a client to use the proxy. Each device gets its own.
_Avoid_: user, account, login

**Egress**:
Where traffic goes to reach the internet — through the upstream when one is configured, directly
otherwise. One setting decides it for every connection.
_Avoid_: route, exit node, egress mode

**Upstream**:
The HTTP proxy that homeproxy hands connections to when an egress other than direct is
configured.
_Avoid_: parent proxy, chained proxy

**Bypass**:
A host list — exact host or `*.suffix` — whose entries use the direct egress and are exempt from the
private-network guard.
_Avoid_: route, whitelist, no-proxy list

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
