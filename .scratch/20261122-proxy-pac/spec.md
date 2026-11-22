# homeproxy — a PAC file for client-side routing

Status: done

## Problem

iOS Wi-Fi has three proxy modes. **Manual** carries a server, a username and a password, and it is
what homeproxy serves today. **Automatic** carries one URL and nothing else: a Proxy
Auto-Configuration (PAC) file. The phone downloads that JavaScript file and asks it, per request,
whether to use a proxy.

Manual sends everything to homeproxy. A PAC can send one host through homeproxy and the next one
direct, so the routing decision moves to the phone. homeproxy builds no such file, so Automatic has
nothing to point at.

## Decision

Serve a generated PAC file at `GET /proxy.pac` on the **proxy port**, built from two new config
keys. The file names homeproxy for ordinary hosts and `DIRECT` for the hosts the operator keeps off
the proxy.

It runs on the proxy port because that port already binds `0.0.0.0`; the management port binds
`127.0.0.1` (miso's default) and reaching it from the phone would publish the whole management
surface.

An origin-form request cannot collide with proxied traffic: a phone fetching the file sends
`GET /proxy.pac`, while everything travelling *through* the proxy arrives in absolute form
(`GET http://host/path`) or as `CONNECT`.

`homeproxy.pac.require-trusted-client` closes the file to addresses outside
`homeproxy.trusted-clients`. It is a bool, default on, and its only gate is the address list: a
client in Automatic mode cannot answer a credential challenge, so a credential path would break the
client the file exists for. An empty `homeproxy.trusted-clients` therefore serves the file to
nobody — a deliberate default-deny, warned about at startup rather than refused, so an existing
config keeps booting.

Accepted consequence: the PAC answers `PROXY <proxy>; DIRECT`, so when homeproxy refuses or is
down, the phone retries the request on its own connection. Convenient, and it means the
private-network guard no longer bounds phone traffic — a `403` can be followed by a direct
connection. This is the chosen trade-off.

## Contract

- Setting `homeproxy.pac.direct`: string list, default empty. A host the phone reaches directly —
  an exact host or a `*.suffix`.
- Setting `homeproxy.pac.proxy`: optional `host:port`, the address the PAC emits. Unset means: host
  from the request's `Host`, port from `homeproxy.port`.
- Setting `homeproxy.pac.require-trusted-client`: bool, default `true`. A PAC fetch from an address
  outside `homeproxy.trusted-clients` is refused with `403` and an empty body; an address inside the
  list is served as usual. No credential is consulted on this path. Turning it off serves the file
  to any address that can reach the proxy port. When it is on and `homeproxy.trusted-clients` is
  empty, every fetch is refused and startup logs a warning.
- Endpoint: `GET /proxy.pac` on `homeproxy.port`, origin-form only (`r.URL` is not absolute).
  Absolute-form requests and `CONNECT` keep today's forward and tunnel paths untouched.
- Order: the PAC branch runs before the credential check. `homeproxy.pac.require-trusted-client`
  gates it on the address list, the only check a client in Automatic mode can satisfy; turning the
  setting off is what makes the file public.
- A PAC fetch whose request `Host` is not a hostname or IP literal is refused with `400` when
  `homeproxy.pac.proxy` is unset; the request `Host` supplies the proxy host only when it is usable.
- Response: `200`, `Content-Type: application/x-ns-proxy-autoconfig`,
  `Cache-Control: no-store`, a JavaScript body.
- Body: `FindProxyForURL(url, host)` returns `"DIRECT"` for a listed host, otherwise
  `"PROXY <proxy>; DIRECT"`. A configured `homeproxy.pac.proxy` is re-emitted as
  `net.JoinHostPort(host, port)` with the port written as a decimal number, so
  `example.com:03128` answers `example.com:3128`; an IPv6 host keeps its brackets.
- Matching mirrors `homeproxy.bypass`: entries are normalized the same way (`HostOnly`: trims
  space, strips the port, IPv6 brackets and trailing dot, lowercased), an exact host, or `*.suffix`
  matching subdomains only. The generated script lowercases the client `host` and strips its IPv6
  brackets before comparing; a PAC `host` carries no port, and the script does not strip a trailing
  dot. `homeproxy.bypass` itself is not consulted — it governs homeproxy's egress, a different
  decision.
- Generated JavaScript uses plain string comparisons. No `shExpMatch`, `dnsResolve`, `isInNet`, and
  no lookup of any kind.
- Startup: a `homeproxy.pac.direct` entry that is not a hostname or IP literal, optionally `*.`
  prefixed, fails startup. So does a `*.` in front of an IP literal and an IP literal carrying a
  zone, both of which the client could never match. A `homeproxy.pac.proxy` that is not `host:port`
  with an all-digit port in 1–65535 fails startup. `homeproxy.pac.require-trusted-client` on with
  an empty `homeproxy.trusted-clients` is not a startup error: the service boots, logs a warning,
  and refuses every PAC fetch.

## Invariants

- A PAC request never reaches the credential check, the private-network guard, the egress choice,
  the upstream, or the tunnel path.
- With `homeproxy.pac.require-trusted-client` set, the only check the PAC path adds is the address
  match against `homeproxy.trusted-clients`; no credential is read, and the proxy's own access rules
  are unchanged.
- Emitted text derives only from validated entries; an entry can never inject JavaScript.
- An empty `homeproxy.pac.direct` emits no `DIRECT` branch.
- Every request that is not an origin-form `GET /proxy.pac` behaves exactly as it does today.

## Acceptance criteria

- [x] `GET /proxy.pac` on the proxy port answers `200` without a credential, with the PAC content
      type and a JavaScript body
- [x] the body defines `FindProxyForURL(url, host)`
- [x] a host in `homeproxy.pac.direct` maps to `DIRECT`; any other host maps to
      `PROXY <proxy>; DIRECT`
- [x] exact and `*.suffix` matching mirror `homeproxy.bypass`, including subdomain-only semantics
      for `*.` and case-insensitive comparison
- [x] `homeproxy.pac.proxy` is emitted when set; when unset the request `Host` supplies the host and
      `homeproxy.port` the port; an IPv6 host is bracketed
- [x] an absolute-form request whose path is `/proxy.pac`, and a `CONNECT` to a host named
      `proxy.pac`, still take the proxy path
- [x] `homeproxy.pac.require-trusted-client` defaults to on: an address outside
      `homeproxy.trusted-clients` receives `403` with an empty body
- [x] an address inside `homeproxy.trusted-clients` receives the file, whether or not it carries a
      credential; an untrusted address carrying a valid credential is still refused
- [x] turning the setting off serves the file to an untrusted address
- [x] on with an empty `homeproxy.trusted-clients`: the service still boots, logs a warning, and
      refuses every PAC fetch
- [x] startup fails on a malformed `homeproxy.pac.direct` entry and on a malformed
      `homeproxy.pac.proxy`
- [x] an empty `homeproxy.pac.direct` produces a body with no `DIRECT` routing branch
- [x] `doc/config.md` documents every key through its `misoconfig-prop` annotation

## Testing Decisions

The existing seam holds: `New(cfg)` returns the handler, tests listen on an ephemeral TCP port and
drive real HTTP. A PAC test sends an origin-form `GET /proxy.pac` and reads the body; the body is
asserted as text, since no JavaScript engine belongs in a Go suite. Implementation runs the
generated file once through `node` by hand and records the result — no `node` dependency lands in
the tests. Config-validation cases go beside the existing ones in `main_test.go`.

## Required Skills

`dev-flow` (lane), `miso` (config properties and defaults), `tdd`, `code-review`.

## Out of scope

- WPAD or auto-discovery; the operator types the URL.
- Editing the PAC at runtime; config is read once at startup.
- A credential-based gate on the PAC endpoint, or reconciling it with `server.auth.bearer`, which
  would block the fetch if set; a client in Automatic mode cannot answer either one.
- Fetching the PAC through the proxy; iOS fetches it directly.
- Trust, credentials, the guard, the egress and the upstream — none of them change.
- Anything on the phone beyond the Automatic URL.
