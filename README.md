# homeproxy

An authenticated forward HTTP proxy for an iPhone's Wi-Fi proxy setting. It accepts absolute-form
HTTP requests and `CONNECT` tunnels, checks Basic credentials from a config file, and forwards to a
configurable upstream proxy (direct when the upstream is empty).

## Build

Local binary:

```bash
go build -o homeproxy .
```

Container image (multi-stage, Go 1.24 builder, distroless non-root runtime):

```bash
docker build -t homeproxy:local .
```

The image runs `/usr/local/bin/homeproxy configFile=/conf/conf.yml` as a non-root user and exposes
only the proxy port, 17890. The config file is mounted at runtime; it is not baked into the image.

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

`compose.yml`:

- publishes **only** `17890` (the proxy port) to the host;
- leaves the management port (`server.port`, default `7990`) unpublished — `/health` and `/metrics`
  are reachable only from inside the container network;
- joins only its own declared network, so other compose projects cannot reach it by name; the
  network is a naming boundary, not an isolation guarantee;
- mounts `conf-prod.yml` read-only at `/conf/conf.yml`.

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
`homeproxy.bypass`) and numeric props (`homeproxy.port`, `homeproxy.dial-timeout-seconds`,
`server.port`) are read as literal values; `${...}` in them is not expanded.

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

Hosts not listed in `homeproxy.bypass` that resolve to a non-public address are refused (the
private-network guard) — loopback, private, link-local, CGNAT, benchmarking, reserved, metadata and
multicast ranges. List a host in `homeproxy.bypass` (exact host or `*.suffix`) when it is yours;
bypassed hosts use the direct egress and are exempt from that guard.
