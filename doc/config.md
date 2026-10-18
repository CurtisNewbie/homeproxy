# Configurations

For more configuration, see [github.com/curtisnewbie/miso](https://github.com/CurtisNewbie/miso/blob/main/doc/config.md).

## Home Proxy Configuration

| property                       | description                                                                                                | default value |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------- | ------------- |
| homeproxy.port                 | Port on which the forward HTTP proxy listens                                                               | 17890         |
| homeproxy.users                | Basic auth credentials allowed to use the proxy, as a list of name/secret entries                          |               |
| homeproxy.upstream             | Upstream proxy address (host:port); empty means direct connections                                         |               |
| homeproxy.upstream.username    | Username for authenticating against the upstream proxy                                                     |               |
| homeproxy.upstream.password    | Password for authenticating against the upstream proxy                                                     |               |
| homeproxy.bypass               | Hosts that bypass the upstream proxy and are exempt from the private-address guard; exact host or *.suffix |               |
| homeproxy.dial-timeout-seconds | Timeout in seconds for dialling a target or upstream, including the upstream CONNECT handshake             | 10            |
| server.port                    | Port of the miso management server                                                                         | 7990          |