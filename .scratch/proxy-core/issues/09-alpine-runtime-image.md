# 09: Alpine runtime image mirroring the house pattern

**What to build:** The container image follows the same shape as the other services in this
workspace: a single-stage Alpine runtime that copies a pre-compiled binary and mounts the config
file, instead of building Go source inside the image.

**Blocked by:** 06 (deployment and configuration docs)

**Status:** done

Verification note: `homeproxy_build` was cross-compiled and checked to be an ELF Linux binary, the
compose file was parsed, and `go build`/`go vet`/`go test` pass. The `docker build` itself was not
executed (no container runtime available in the implementation environment).

- [x] the Dockerfile is a single `alpine:3.17` stage with `tzdata`, `WORKDIR /usr/src/`, a copy of the pre-compiled `homeproxy_build` binary as `./app_homeproxy`, `TZ=Asia/Shanghai`, and `CMD ["./app_homeproxy", "configFile=/usr/src/config/conf.yml"]`
- [x] no Go build stage remains; the image contains only the pre-compiled binary and the runtime packages
- [x] the compose file mounts `conf-prod.yml` at `/usr/src/config/conf.yml`, still publishes only the proxy port, and still joins only its own declared network
- [x] `homeproxy_build` is git-ignored and is included in the Docker build context
- [x] the README documents the cross-compile command, `docker build`, and the in-image config path
- [x] the ticket 06 properties still hold: only the proxy port is published, the management port is unpublished, and `${ENV}` string expansion in `conf-prod.yml` works
