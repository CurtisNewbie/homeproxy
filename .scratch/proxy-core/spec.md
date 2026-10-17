# homeproxy — authenticated forward HTTP proxy

Status: ready-for-agent

## Problem Statement

I want my iPhone to reach my home egress from any Wi-Fi network, without depending on the
upstream proxy's own configuration. If the upstream proxy (`host:port` my other tools use) changes,
dies, or I decide to drop it and use the machine directly, the phone must keep working and only
the server-side config should change.

The phone's Wi-Fi proxy setting can only speak plain HTTP proxy (absolute-form requests plus
`CONNECT` tunnels) with Basic auth. It has no SOCKS option, no TLS-to-proxy option, and cannot
send a JWT. Anything device-wide would require supervising (and erasing) the phone.

## Solution

`homeproxy`: a small standalone Go service that listens on its own port, authenticates Basic
credentials taken from its config file, and forwards every request through a configurable
upstream proxy — or directly when no upstream is configured, and for hosts the config marks as
yours. The phone is configured once with `host`, `port`, `username`, `password` and never needs
to change when the upstream changes. Any other host that resolves to a private address is
refused, so the proxy is not a doorway into the local network.

Credentials are static config values with no database, no external identity service and no user
management: rotating a secret means editing `conf.yml` and restarting.

## User Stories

1. As the phone owner, I want to enter one host, port, username and password in iOS Wi-Fi proxy settings, so that all HTTP/HTTPS traffic from that network goes through my home egress.
2. As the phone owner, I want HTTPS sites to work through the proxy, so that normal browsing is unaffected.
3. As the phone owner, I want plain-HTTP sites to work too, so that the proxy is a complete HTTP proxy and not a CONNECT-only stub.
4. As the phone owner, I want a wrong or missing password to be rejected, so that the port is not an open proxy.
5. As the phone owner, I want iOS to prompt once for credentials and then keep working, so that the proxy's 407 challenge behaves the way iOS expects.
6. As the phone owner, I want to point the proxy at an upstream proxy by config only, so that switching egress does not require touching the phone.
7. As the phone owner, I want to switch to direct egress by clearing one config value, so that an upstream outage is not an outage of my phone's proxy.
8. As the phone owner, I want several named credentials, so that I can issue one per device and revoke one without breaking the others.
9. As the phone owner, I want credentials to be per-name rather than shared, so that logs can attribute traffic to a device.
10. As the operator, I want a startup failure when no credentials are configured, so that a misconfiguration cannot silently create an open proxy.
11. As the operator, I want per-tunnel logs (user, target, bytes, duration, result), so that I can see what the proxy is doing and who is using it.
12. As the operator, I want credentials never to appear in logs, so that log files are not a credential store.
13. As the operator, I want `/health` and `/metrics` on a separate local port, so that the proxy's own port stays a pure proxy surface.
14. As the operator, I want bytes, auth failures, active tunnels and dial latency exposed as metrics, so that I can alert on abuse or breakage.
15. As the operator, I want the process to shut down cleanly on SIGTERM, closing the listener and active tunnels, so that redeploys do not hang.
16. As the operator, I want a dial timeout and no idle timeout on tunnels, so that slow targets fail fast while long-lived connections survive.
17. As the operator, I want the upstream's own Basic credentials configurable, so that an authenticated upstream also works.
18. As a developer, I want a single seam to test the proxy against a real listener and a fake upstream, so that tests exercise real HTTP behaviour rather than mocks.
19. As the phone owner, I want an upstream failure to surface as a clear proxy error for that request only, so that a dead upstream does not wedge the listener.
20. As a client other than the phone (e.g. a script or another tool), I want preemptive Basic on `CONNECT` to be accepted, so that non-challenging clients work without special cases.
21. As the phone owner, I want my own domain to go direct instead of through the upstream, so that reaching my own services does not depend on the VPN.
22. As the phone owner, I want a host that resolves to a private address refused unless I listed it, so that a leaked credential cannot reach my LAN.
23. As the operator, I want the private-address rule on by default with no off switch, so that the proxy cannot silently become a LAN gateway.
24. As the operator, I want the chosen egress and any policy denial in the log line, so that I can tell why a request failed.
25. As the operator, I want the bypass list to double as the private-address exemption, so that "these hosts are mine" is stated in one place.

## Implementation Decisions

Stack: Go 1.24.4, module `github.com/curtisnewbie/homeproxy`, miso pinned to
`v0.4.16-0.20260718082143-e47321d5d9b6`.

Two listeners:

- Proxy listener on `homeproxy.port` (default `17890`): a raw `net.Listen` + `net/http.Server` owned by the service, started in a miso `PreServerBootstrap` callback and closed from a miso shutdown hook. It is not miso's HTTP server, because the proxy needs connection hijacking and CONNECT requests carry no usable path for gin routing.
- Management listener: miso's own HTTP server stays enabled on `server.port` (default `7990`), serving `/health` and `/metrics`. Consul is disabled.
- Startup fails if the two ports are equal, or if the credential list is empty.

Configuration (all under `homeproxy.*` plus the miso `server.*` keys):

| Prop | Default | Meaning |
|---|---|---|
| `homeproxy.port` | `17890` | proxy listener port |
| `homeproxy.upstream` | empty | upstream HTTP proxy as `host:port`; empty = direct |
| `homeproxy.upstream.username` | empty | Basic username for the upstream proxy |
| `homeproxy.upstream.password` | empty | Basic secret for the upstream proxy |
| `homeproxy.users` | none | list of `{name, secret}` in plaintext; startup fails when empty |
| `homeproxy.bypass` | none | host list, exact or `*.suffix`; matches route direct and may resolve private |
| `homeproxy.dial-timeout-seconds` | `10` | dial + upstream CONNECT handshake timeout |

Authentication: `Proxy-Authorization: Basic base64(name:secret)` read whenever present, so both
challenge-based clients (iOS) and preemptive clients that send credentials on the first request work. Missing or
invalid credentials produce `407 Proxy Authentication Required` with
`Proxy-Authenticate: Basic realm="homeproxy"`, `Content-Length: 0`, connection kept open — iOS
retries on the same connection after the challenge. Secrets are compared in constant time; an
unknown name and a wrong secret are indistinguishable in the response and the log.

Forwarding: one egress seam. The target host is resolved first, then the egress is chosen:

| # | Condition | Result |
|---|---|---|
| 1 | host matches `homeproxy.bypass` | dial the target directly, private addresses permitted |
| 2 | otherwise, any resolved address is loopback, private, link-local, CGNAT, metadata or multicast | `403`, nothing dialled |
| 3 | otherwise, `homeproxy.upstream` is set | dial the upstream, send `CONNECT target`, add `Proxy-Authorization` when upstream credentials are configured, require `200`, return the tunnelled connection |
| 4 | otherwise | dial the target directly |

Bypass matching is exact host or `*.suffix` (subdomains only), case-insensitive, port ignored.
Resolution results are cached briefly per host so a connection does not pay a lookup per request.
The check is best-effort on the upstream path: the upstream resolves again and may disagree, which
is accepted rather than intercepted. When resolution itself fails, the request is handed to the
upstream when one is configured and answered `502` when it is not, with the failure logged.

`CONNECT` requests hijack the client connection, dial through that seam, answer
`200 Connection Established`, then copy both directions, half-closing each side on EOF. A dial
failure answers `502` on the normal HTTP path, before hijacking.

Absolute-form requests (`GET http://host/path`) are forwarded with a `http.Transport` whose
`DialContext` is the same seam, so chaining and direct mode are identical for both request kinds.
Hop-by-hop headers and `Proxy-Authorization`/`Proxy-Connection` are stripped before forwarding;
`Connection` token lists are honoured per RFC 7230. A non-absolute request path answers `400`.

Logging: one line per finished tunnel or forwarded request — user name, target, bytes up/down,
duration, outcome. Auth failures log remote address and user name only. Credentials, config
secrets and `Proxy-Authorization` values never reach logs.

Metrics: `homeproxy_bytes_up_total`, `homeproxy_bytes_down_total`,
`homeproxy_auth_failures_total`, `homeproxy_requests_total` (counter), active tunnels as a
hand-registered gauge (`homeproxy_tunnels_active`), and `homeproxy_dial_duration` histogram.
miso has no gauge factory, so the gauge is registered on `prometheus.DefaultRegisterer`
directly.

`doc/config.md` is generated from `misoconfig-*` annotations; a `conf.yml` and a `conf-prod.yml`
with `${ENV}` expansion ship with the repo.

## Testing Decisions

Good tests drive the proxy as a client would: real TCP, real HTTP, real bytes. They assert
external behaviour (status lines, headers, bodies, bytes arriving) and never internal function
calls or log strings.

Single seam: the proxy is constructed from a config value — `newProxy(cfg)` returns the handler
plus the dialer — and started on an ephemeral port. Tests start two fixture servers alongside it:
a fake upstream proxy that records the `CONNECT` requests and credentials it received, and plain
HTTP/echo servers as targets.

Covered at that seam:

- missing credentials → `407` with `Proxy-Authenticate`; unknown user and wrong secret behave identically.
- valid credentials → `CONNECT` tunnel carries bytes to a local TLS target and back.
- absolute-form `GET` through the proxy returns the target's response, and `Proxy-Authorization` is not forwarded.
- upstream configured → the fake upstream receives `CONNECT target` (with its credentials when configured) and the client still gets the response.
- upstream empty → the fake upstream receives nothing and the target is dialled directly.
- upstream refusing `CONNECT` → `502` to the client, listener still serving the next request.
- hop-by-hop headers stripped; non-absolute request path → `400`.
- half-close: client closing its write side does not truncate the response.
- a bypass host is dialled direct even with an upstream configured, and a bypass host resolving private is allowed.
- a non-bypass host resolving private → `403`, with no upstream and no target connection dialled.
- a bypass host resolving public still routes direct rather than upstream.

No prior test art exists in this repo; the standard library's `httptest.Server` and
`httptest.NewTLSServer` provide the targets, and the fake upstream is a hand-written
`net/http` server that answers `CONNECT` and records requests.

## Out of Scope

- credential database, external identity service, admin UI, per-user approval flow.
- SOCKS5, UDP/QUIC, TLS interception or MITM, HTTP/2 to clients.
- iOS supervision/MDM and Global HTTP Proxy payloads; the phone is configured per Wi-Fi network by hand.
- Per-IP throttling, rate limiting, connection caps, IP allowlists.
- CIDR, geo or geosite-based routing; only exact hosts and `*.suffix` are matched.
- Serving a PAC file or any client-side per-domain routing.
- Hot configuration reload; rotating credentials requires a restart.
- Multi-user quotas and per-user bandwidth accounting beyond the log line.

## Further Notes

The upstream chain is uniform: both `CONNECT` tunnels and plain HTTP requests are dialled
through the same seam, so there is exactly one place where "how do I reach the internet" is
decided.

The port is plain HTTP by necessity — iOS sends proxy credentials in cleartext Basic and cannot
speak TLS to a proxy. Deployment should therefore use a long random secret per device, and the
port should be treated as public-but-credentialled rather than trusted.
