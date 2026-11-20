# 06: Deployment and configuration docs

**What to build:** The service can be built and deployed as a container whose only published port
is the proxy port, with configuration examples that document every key.

**Blocked by:** 02 (credential-gated CONNECT tunnel, direct egress)

**Status:** done

- [x] a multi-stage Dockerfile produces an image running the service from a mounted config file
- [x] the compose file publishes the proxy port and leaves the management port unexposed to the host
- [x] the compose file attaches the service to its own network, with no route by name to any other application's containers
- [x] `conf.yml` and `conf-prod.yml` exist, with the production file expanding `${ENV}` variables
- [x] every configuration key appears in one table in `doc/config.md`, generated from the config annotations
- [x] the README states how to build, run and configure, including the phone-side settings (server, port, credential)
