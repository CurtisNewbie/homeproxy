# homeproxy — trusted clients

Status: done

## Problem

Some clients read the Wi-Fi proxy but cannot answer its challenge. The Weibo iOS app is the case in
hand: it sends `CONNECT api.weibo.cn:443` with no `Proxy-Authorization`, receives `407`, and does not
retry with credentials — 26 rejections in one session, 2 authenticated retries. The app then reports
网络不可用. Safari, images and the app's SDK endpoints authenticate through CFNetwork and work, so the
proxy is not at fault and no credential-side change can fix such a client.

A device on a network the operator already trusts must be able to use the proxy without a credential.

## Decision

Add `homeproxy.trusted-clients`: a list of IPv4/IPv6 addresses and CIDRs. A request whose socket
address matches skips the credential check. Nothing else changes — the private-network guard still
applies, `homeproxy.bypass` still decides the egress, and the upstream is untouched.

## Contract

- Setting: `homeproxy.trusted-clients`, string list, parsed once at construction. Default empty,
  which leaves today's behaviour exactly as it is.
- Match: the host part of the connection's `RemoteAddr`, against each entry as a single address or a
  CIDR; IPv4 and IPv6; an IPv4-mapped IPv6 client matches an IPv4 entry. Case, port and DNS play no
  part — no reverse lookup.
- Precedence: a valid credential from a trusted address keeps its own name (`credential=<name>`); a
  missing or wrong credential from a trusted address is allowed and logged as
  `credential=trusted:<ip>`. Both lines carry `trusted=true`; a request from an untrusted address
  keeps today's line shape.
- Startup: a malformed entry fails startup, and so does any list containing `0.0.0.0/0` or `::/0`.
- Logging never carries a secret; the trusted form carries only the source address.

## Invariants

- A client outside the list sees no change at all, including its `407` and its log line.
- Trust never reaches a target the private-network guard refuses.
- Trust never changes which egress a request takes.

## Acceptance criteria

- [x] a single address in the list is trusted; a CIDR trusts every address inside it; an address
      outside it still receives `407`
- [x] an IPv6 client matches an IPv6 entry, and an IPv4-mapped client matches an IPv4 entry
- [x] both a `CONNECT` tunnel and a plain forward accept a trusted client
- [x] a trusted client with a valid credential logs that credential's name with `trusted=true`
- [x] a trusted client with no credential or a wrong one is allowed and logs `credential=trusted:<ip>`
- [x] a trusted client asking for a private target still gets `403`
- [x] startup fails on a malformed entry, on `0.0.0.0/0`, and on `::/0`
- [x] an empty list reproduces today's behaviour; existing tests pass unchanged
- [x] `doc/config.md` documents the key through its `misoconfig-prop` annotation

## Testing Decisions

The existing single seam holds: `newProxy(cfg)` returns the handler and dialer, tests start it on an
ephemeral port and drive real TCP. New cases set `TrustedClients` on that config and reuse the
fixture servers; a test trusts `127.0.0.0/8` to stand in for the device.

## Required Skills

`dev-flow` (lane), `miso` (config property and defaults), `tdd`, `code-review`.

## Out of scope

- trust by hostname, user-agent, credential name, or an authenticated first request
- a TTL or any address that becomes trusted by authenticating once
- trust affecting the egress, the private-network guard, or the management port
- configuration reload; the list is static like the credentials
- anything changed on the phone side