# The proxy runs its own listener, outside the HTTP API gateway

The proxy must hold hijacked, long-lived `CONNECT` tunnels. An HTTP API gateway routes by request
path and forwards with a reverse proxy: `CONNECT` arrives in authority-form with no path, so
neither target resolution nor path-based authorization applies to it, and a reverse proxy cannot
tunnel bytes. The proxy therefore owns a `net/http.Server` on its own port, with the framework's
HTTP server kept only for health and metrics. A second, separate listener also keeps a public
tunnelling surface out of the process that authorizes the rest of the system.
