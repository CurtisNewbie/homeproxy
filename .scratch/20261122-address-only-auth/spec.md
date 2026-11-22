# homeproxy — address-only access

Status: done

## Problem

`homeproxy.users` must hold at least one name/secret entry, so a deployment that authorizes every
client by address — a phone on a trusted LAN — has to invent a credential nobody uses. The service
then advertises a Basic challenge for a secret that will never be presented, and the operator
carries a value with no purpose.

Address trust is already a complete authorization story on its own: a trusted client skips the
credential check, and every other client is refused.

## Decision

Startup accepts an empty `homeproxy.users` when `homeproxy.trusted-clients` is non-empty. At least
one of the two must be configured; configuring neither still fails startup. Nothing else changes.

## Contract

- Startup fails only when both `homeproxy.users` and `homeproxy.trusted-clients` are empty. The
  error names both keys.
- With no credentials, `authenticate` never matches, so a request from an untrusted address gets
  the existing `407` challenge — one that no credential can satisfy. Unchanged here and accepted;
  the port stays closed to those addresses.
- A trusted address is allowed exactly as today, with the existing log shape.
- The private-network guard, the egress, the bypass list, the PAC endpoint and the upstream are
  untouched.
- The `homeproxy.users` annotation says the list is optional when trusted clients are configured, so
  `doc/config.md` carries the rule.

## Invariants

- A request is allowed only when it carries a valid credential or arrives from a trusted address.
- An empty credential list never widens access: it removes one way to be allowed, not the check.
- Configuring neither list is still a startup error.

## Acceptance criteria

- [x] an empty `homeproxy.users` with a non-empty `homeproxy.trusted-clients` starts the service
- [x] both empty fails startup, naming both keys
- [x] no credentials plus an untrusted address still answers `407` and forwards nothing
- [x] no credentials plus a trusted address is allowed, as today
- [x] credentials set with an empty trusted list behaves exactly as before
- [x] `doc/config.md` states that `homeproxy.users` is optional when trusted clients are configured

## Testing Decisions

The existing seams hold: `validate` through `internal/config`'s unit tests, the request path through
`newProxy(cfg)` on an ephemeral port, and startup through the process tests in `main_test.go`.

## Required Skills

`dev-flow` (lane), `miso` (config properties and defaults), `tdd`, `code-review`.

## Out of scope

- answering `403` instead of `407` when no credential exists
- any change to trusted-client matching, the PAC gate, or the egress