# Managed clash

**Status:** done

## Problem

homeproxy can reach a clash-compatible instance through its controller. That instance's selector group
does not stay where it was put: a config swap or reload resets it to whichever member the config
lists first, and a change made in a clash dashboard has no owner either. So somebody re-picks the
member by hand after every refresh, and it silently drifts whenever anyone else touches the
instance.

## Decision

homeproxy keeps one selector group pointed at the preferred member, and nothing else.

Every `managed-clash.interval` it reads the selector through the controller and sets it back when it
has drifted. Clash keeps node health and node choice: when the configured member is a
`URLTest`/`Fallback` group it picks its own node, so homeproxy never calls a delay endpoint and never
pins a node. Subscription refresh stays outside homeproxy entirely.

## Contract

Props, all under `managed-clash.`:

| prop | type | default | meaning |
|---|---|---|---|
| `managed-clash.enabled` | bool | `false` | nothing runs unless set |
| `managed-clash.controller` | string | `http://localhost:9990` | controller base URL |
| `managed-clash.secret` | string | empty | bearer secret; empty means no auth header |
| `managed-clash.selector` | string | empty | the selector group homeproxy manages |
| `managed-clash.proxy-name` | string | empty | the proxy to keep selected in that selector |
| `managed-clash.interval` | duration | `15m` | between drift checks |

Load-time validation refuses to start when `enabled` is true with an empty `controller`, an empty
`selector`, an empty `proxy-name`, or a non-positive `interval` — mirroring the existing credential
and port checks. A wrong controller, selector, or proxy name is not a config error: it is discovered
at runtime and never blocks serving.

One cycle, run at startup and then every `interval`, off the request path:

1. `GET {controller}/proxies/{selector}` — the selector must exist and be a group whose `all`
   contains `proxy-name`. If `now` already equals `proxy-name`, the cycle ends with no write.
2. `PUT {controller}/proxies/{selector}` with `{"name": "<proxy-name>"}`; `204` is success.

Common rules:

- Names are URL-path-escaped, so emoji and CJK names work as they are.
- The controller URL must be reachable from wherever homeproxy runs; nothing assumes it is local, and
  a container's `localhost` is not the clash host.
- `Authorization: Bearer <secret>` is sent only when `secret` is set.
- Transient failures (transport, `5xx`, `401`/`403`) are retried with bounded backoff inside the
  cycle, giving up after about a minute and leaving the next cycle to try again. Permanent ones
  (`404`, `400`, `proxy-name` absent from `all`) log once for that cycle and are not retried.
- One info line when a cycle writes, one debug line when it finds the selection already correct, one
  warning when a cycle fails.
- The secret never appears in a log line.

Invariants:

- homeproxy never refreshes the subscription, runs no script, reloads no config, and never reads,
  parses, or writes the clash config. It knows a controller URL, a secret, and two names.
- Management never touches egress, bypass, PAC, listeners, or `homeproxy.upstream.*`; the managed
  instance need not be homeproxy's upstream.
- A wrong selection is corrected within one `interval`; a manual change in a clash dashboard does not
  survive the next cycle. That is the point of the feature.
- `enabled: false` means no controller call at all.

Out of scope: refreshing the clash config and any script that does it, reloading it, latency testing,
pick-fastest, switching clash mode, a status endpoint, reading the clash config.

## Acceptance criteria

- [x] `enabled: false` → no HTTP request reaches the controller.
- [x] Startup with `now` already `proxy-name` → one `GET`, no `PUT`, no info line.
- [x] Startup with `now` different → `GET`, then `PUT` with body `{"name":"<proxy-name>"}`; `204` accepted,
      one info line.
- [x] Next cycle after an external change to `now` → `PUT` restores `proxy-name`.
- [x] Interval defaults to `15m` and a configured value is honoured.
- [x] Emoji/CJK selector and proxy names reach clash correctly escaped.
- [x] Secret set → `Authorization: Bearer` header; secret empty → no header.
- [x] Selector `404`, or `proxy-name` absent from `all` → no `PUT`, one warning, cycle ends.
- [x] Controller unreachable → the proxy serves normally, in-cycle retries are bounded, next cycle
      retries.
- [x] `enabled: true` with empty `controller`, `selector`, or `proxy-name`, or a non-positive
      `interval` → startup fails with a config error.
- [x] `doc/config.md` regenerated (`misoconfig`) and the two sample configs carry the block,
      commented out and disabled.
- [x] No new metric series; the existing ones are untouched.
- [x] `go test ./...` green.

## Required skills

`dev-flow`, `miso`, `tdd`, `code-review` — per `AGENTS.md`.

## Test seams (to confirm)

- `internal/clash`: unit tests against an `httptest` fake controller — request shape, escaping, auth
  header, idempotent skip, drift correction, transient/permanent classification.
- `internal/config`: `validate()` table cases for the new failures and the accepted shape.
- One subprocess test in `main_test.go` style: enabled config + fake controller, asserting the
  selection `PUT`; plus the disabled case asserting no request arrives.
