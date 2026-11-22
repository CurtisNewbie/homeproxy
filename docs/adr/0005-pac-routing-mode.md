# The PAC routing mode decides which way the exception list runs

The first PAC shipped one list and one direction: every host answered
`PROXY <proxy>; DIRECT`, and `homeproxy.pac.direct` named the hosts that skipped the proxy. That is
the right default only when the intent is "route the internet through homeproxy". An operator who
wants the opposite — a handful of hosts through homeproxy, everything else direct — cannot express
it, because naming the internet as an exemption list is not a configuration anyone will maintain.

`homeproxy.pac.mode` makes the direction explicit and defaults to `direct`:

- `direct` — every host answers `DIRECT`, except the entries in `homeproxy.pac.proxy-hosts`, which
  answer `PROXY <proxy>; DIRECT`. Only this list is consulted.
- `proxy` — every host answers `PROXY <proxy>; DIRECT`, except the entries in `homeproxy.pac.direct`,
  which answer `DIRECT`. Only this list is consulted.

Two lists, one consulted per mode. A list with entries that the active mode never reads logs one
startup warning and does not block startup: flipping the mode should not force an edit of both
lists, and a silently ignored list is worse than a loud one.

Rejected: one list whose meaning flips with the mode. It reads shorter, but the same list would mean
opposite things in two configs, and a copied entry would silently invert.

The proxied answer keeps its `; DIRECT` fallback. Direct is the default in the new mode, so a
falling-back host is already a host the operator chose to proxy; the fallback only decides whether a
dead homeproxy fails the request or lets it through unproxied. That trade was taken deliberately
when the file was first designed and is unchanged here.