# Proxy credentials are static configuration

Clients of this proxy authenticate with a name and secret held in `conf.yml`. There is no
credential database, no identity service call and no management API. Two forces decide this: the
proxy is the path to the internet, so it must keep serving when every other service is down, and
the credential set is a handful of device secrets owned by one operator, where rotation by config
edit and restart is cheaper than a schema, an approval flow and a UI. The cost is accepted
deliberately: revocation requires a restart, and there is no per-user history beyond the log line.
