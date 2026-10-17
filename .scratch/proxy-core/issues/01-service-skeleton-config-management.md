# 01: Service skeleton, config, management surface

**What to build:** A runnable service that loads its configuration, refuses unsafe configuration,
serves health and metrics on the management port, and owns a proxy port that currently answers
every request with the authentication challenge.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `./homeproxy configFile=conf.yml` starts and logs a startup line naming both ports
- [ ] an empty `homeproxy.users` list aborts startup with a clear message
- [ ] `homeproxy.port` equal to `server.port` aborts startup with a clear message
- [ ] `GET /health` on the management port returns 200
- [ ] `GET /metrics` on the management port returns Prometheus text output
- [ ] the proxy port accepts a TCP connection and answers both an absolute-form `GET` and a `CONNECT` with `407` and `Proxy-Authenticate: Basic realm="homeproxy"`
- [ ] SIGTERM closes the proxy listener and exits 0
