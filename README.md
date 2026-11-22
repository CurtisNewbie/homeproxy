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
mounted from the host at runtime; it is not baked into the image. The image itself declares no
exposed ports; compose publishes only the proxy port, 17890.

## Run locally

```bash
./homeproxy configFile=conf.yml
```

`conf.yml` in the repo is a development config: proxy on `17890`, management surface on `7990`,
one credential (`phone` / `change-me`). Change the secret before exposing the port. The management
port serves `/health` and `/metrics` only; keep it on localhost.

## Run with Docker Compose

```bash
# Optional: exported variables fill the ${...} placeholders in conf-prod.yml.
export HOMEPROXY_UPSTREAM=upstream.example:3128
export HOMEPROXY_UPSTREAM_USERNAME=upstream-user
export HOMEPROXY_UPSTREAM_PASSWORD=upstream-secret

docker compose up -d --build
```

The compose build only copies the pre-compiled `homeproxy_build`; run the Linux build step from
[Build](#build) first.

`compose.yml`:

- publishes **only** `17890` (the proxy port) to the host;
- leaves the management port (`server.port`, default `7990`) unpublished — `/health` and `/metrics`
  are reachable only from inside the container network;
- joins only its own declared network, so other compose projects cannot reach it by name; the
  network is a naming boundary, not an isolation guarantee;
- mounts `conf-prod.yml` read-only at `/usr/src/config/conf.yml`.

Secrets: replace the placeholder `homeproxy.users` entry in `conf-prod.yml` with a long random
secret per device before deploying (edit the host file; it is mounted, not copied).

## Configure

Every key the service reads is documented in one table, generated from the config annotations:
[doc/config.md](doc/config.md). The table also covers the miso management port. Regenerate it with
`misoconfig -path doc/config.md`; do not edit the generated table by hand. Config is read once at
startup; rotating a credential or changing the upstream means editing the file and restarting.

`${VAR}` / `${VAR:default}` expansion applies **only to string props** — `homeproxy.upstream`,
`homeproxy.upstream.username`, `homeproxy.upstream.password` — because those are read as strings,
and miso expands the placeholder when it reads a string prop. List props (`homeproxy.users`,
`homeproxy.bypass`, `homeproxy.pac.direct`, `homeproxy.pac.proxy-hosts`), numeric props
(`homeproxy.port`, `homeproxy.dial-timeout-seconds`, `server.port`) and boolean props
(`homeproxy.pac.require-trusted-client`) are read as literal values; `${...}` in them is not
expanded.

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
  lists match an exact host or a `*.suffix`, and only the list belonging to the active mode is read;
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
list decides the phone's. A host reachable only from the home network — `curtisnewbie.com` in the
sample — must stay off the PAC direct list, or the phone tries it directly and fails whenever it is
away from home.

Hosts not listed in `homeproxy.bypass` that resolve to a non-public address are refused (the
private-network guard) — loopback, private, link-local, CGNAT, benchmarking, reserved, metadata and
multicast ranges. List a host in `homeproxy.bypass` (exact host or `*.suffix`) when it is yours;
bypassed hosts use the direct egress and are exempt from that guard.
