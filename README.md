# homeproxy

An authenticated forward HTTP proxy for an iPhone's Wi-Fi proxy setting. It accepts absolute-form
HTTP requests and `CONNECT` tunnels, authorizes a client by Basic credential or by trusted address,
and forwards to a configurable upstream proxy (direct when the upstream is empty). It also generates
a PAC file, so the phone can send one host through the proxy and another one direct.

## Build

Local binary:

```bash
go build -o homeproxy .
```

Container image: the Dockerfile does not compile Go source. Build the Linux binary first, then copy
it into a single-stage Alpine image:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o homeproxy_build .
docker build -t homeproxy:local .
```

`GOOS`/`GOARCH` must match the Docker host, e.g. `GOARCH=arm64` on Apple Silicon.

The image is one Alpine stage (`alpine:3.17` with `tzdata`) that copies `homeproxy_build` in as
`./app_homeproxy` and starts it with `configFile=/usr/src/config/conf.yml`. The config file is
mounted from the host at runtime; it is not baked into the image. The image declares no ports —
the deployment decides what to publish.

## Run locally

```bash
./homeproxy configFile=conf.yml
```

`conf.yml` in the repo is a development config: proxy on `17890`, management surface on `7990`,
one credential (`phone` / `change-me`). Change the secret before exposing the port. The management
port serves `/health` only; keep it on localhost. Metrics are off in both sample configs.

## Run with Docker

The image carries the binary only; the config is mounted. The deployment owns the compose file:

```bash
docker run -d --name homeproxy \
  -p 17890:17890 \
  -v "$PWD/conf-prod.yml:/usr/src/config/conf.yml:ro" \
  homeproxy:local
```

Publish only `17890`. The management port (`server.port`, default `7990`) serves `/health`; leave it
inside the container network. `${VAR}` placeholders in `conf-prod.yml` are expanded from the
container environment, so `-e HOMEPROXY_UPSTREAM=…` fills them without rebuilding.

`conf-prod.yml` ships without credentials and with an empty `trusted-clients`, so a container
started from it exits at once. Fill in `trusted-clients`, or add a `users` entry, before starting.

## Configure

Every key the service reads is documented in one table, generated from the config annotations:
[doc/config.md](doc/config.md). The table also covers the miso management port. Regenerate it with
`misoconfig -path doc/config.md`; do not edit the generated table by hand. Config is read once at
startup; rotating a credential or changing the upstream means editing the file and restarting.

`${VAR}` / `${VAR:default}` expansion applies **only to string props** —
`homeproxy.upstream.address` (and the deprecated alias `homeproxy.upstream`),
`homeproxy.upstream.username`, `homeproxy.upstream.password` — because those are read as strings,
and miso expands the placeholder when it reads a string prop. List props (`homeproxy.users`,
`homeproxy.bypass`, `homeproxy.pac.direct`, `homeproxy.pac.proxy-hosts`), numeric props
(`homeproxy.port`, `homeproxy.dial-timeout-seconds`, `server.port`) and boolean props
(`homeproxy.pac.require-trusted-client`) are read as literal values; `${...}` in them is not
expanded.

## Managed clash (optional, off by default)

A clash-compatible instance's selector group does not stay where it was put: a config swap or
reload resets it to whichever member the config lists first, and a change made in a clash dashboard
has no owner either. With `managed-clash.enabled` the service keeps one selector group on one
configured member — at startup and again every `managed-clash.interval` it reads
`GET /proxies/{selector}`, and only when `now` differs does it `PUT {"name":"<proxy-name>"}`.

- It knows a controller URL, a secret, and two names. It never reads, parses, or writes the clash
  config, never reloads it, and never fetches a subscription — refreshing that file is the
  operator's own job.
- Clash keeps node choice. When the configured member is a `URLTest` or `Fallback` group, that group
  picks its own node; the service never calls a delay endpoint and never pins a node.
- It is independent of this proxy's egress: the managed instance need not be the upstream, and
  `homeproxy.upstream.*`, the PAC file, and the listeners are untouched.
- Here the controller must be reachable from wherever the service runs — inside a container,
  `localhost` is the container, so use the clash host's LAN address (or `host.docker.internal`).
- Failures never block serving. Transport errors, `401`/`403`, and `5xx` are retried inside the
  cycle for about a minute and then left to the next cycle; a `400`, a `404`, or a member absent
  from the selector's `all` warns once for that cycle and is not retried. A manual dashboard change
  is corrected within one interval — that is the point of the feature.
- `enabled: true` with an empty controller, selector, or proxy name, or a non-positive `interval`,
  refuses to start. A wrong controller, selector, or name is a runtime warning, not a config error.

`interval` is a Go duration (`15m`, `90s`); a bare number means nanoseconds.

## Phone settings

On the phone: **Settings → Wi-Fi → (i) next to the network → Configure Proxy → Manual**.

| Field | Value |
|---|---|
| Server | host or IP running homeproxy |
| Port | `17890` |
| Authentication | on |
| Username | a `name` from `homeproxy.users` |
| Password | that entry's `secret` |

One credential per device, so a single device can be revoked without breaking the others. The proxy
port is plain HTTP with Basic auth (iOS cannot speak TLS to a proxy), so treat it as
public-but-credentialled: use a long random secret rather than a memorable one, and give each device
its own.

A device can also be authorized by address instead, through `homeproxy.trusted-clients`. Those
clients skip the credential check, so `homeproxy.users` may be left empty; configure at least one of
the two lists or the service refuses to start.

### Automatic (per-host routing)

Manual sends every request to homeproxy. **Automatic** takes one URL and lets the phone decide per
request. Point it at the generated file:

**Configure Proxy → Automatic**, URL `http://<host>:17890/proxy.pac`

- `homeproxy.pac.mode` decides the direction. `direct` (the default) sends only the hosts in
  `homeproxy.pac.proxy-hosts` through homeproxy and everything else direct; `proxy` does the
  reverse, sending everything through homeproxy except the hosts in `homeproxy.pac.direct`. Both
  lists take an exact host, which covers that host alone, or a `*.suffix`, which covers the suffix
  itself and every host under it — so `*.youtube.com` covers `youtube.com` as well, and nothing
  expresses "subdomains only". Only the list belonging to the active mode is read;
  the other one logs a warning at startup if it has entries.
- `PROXY <proxy>` is `homeproxy.pac.proxy` when set, otherwise the request's `Host` with
  `homeproxy.port`.
- the file is served without a credential, because iOS ignores `ProxyUsername` and `ProxyPassword`
  in Automatic mode. `homeproxy.pac.require-trusted-client` (default on) serves it only to addresses
  in `homeproxy.trusted-clients`; anything else gets `403`. With no trusted clients the file goes to
  nobody and startup logs a warning. Set it to `false` to serve the file to anything that can reach
  the proxy port.
- `; DIRECT` is a fallback path: when homeproxy is down or refuses a request, the phone retries it
  on its own connection. That includes the private-network guard, so a refused target can still be
  reached directly by the phone.

The PAC direct list is **not** `homeproxy.bypass`. Bypass decides homeproxy's own egress; the PAC
list decides the phone's. A host reachable only from the home network — `nas.home.arpa` in the
sample — must stay off the PAC direct list, or the phone tries it directly and fails whenever it is
away from home.

Hosts not listed in `homeproxy.bypass` are checked by the private-network guard before anything is
dialled, and refused with `403` when the target is a non-public address: an IP literal in loopback,
private, link-local, CGNAT, benchmarking, reserved, metadata or multicast ranges; a local-only name
such as `router`, `nas.local` or `x.internal`; or a name that resolves to one of those ranges. The
last check runs only where homeproxy resolves the name itself — a direct dial, or `egress: all`. A
target the PAC routes through the upstream is handed over untouched, because the upstream resolves
it again. List a host in `homeproxy.bypass` (exact host, or `*.suffix` covering the suffix and its
subdomains) when it is yours; bypassed hosts use the direct egress and are exempt from that guard.
The guard is on by default; `homeproxy.private-network-guard: false` turns every one of these checks
off and logs a warning at startup.
