# Configurations

For more configuration, see [github.com/curtisnewbie/miso](https://github.com/CurtisNewbie/miso/blob/main/doc/config.md).

## Home Proxy Configuration

| property                             | description                                                                                                     | default value |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------- |
| homeproxy.port                       | Port on which the forward HTTP proxy listens                                                                    | 17890         |
| homeproxy.users                      | Basic auth credentials allowed to use the proxy, as a list of name/secret entries                               |               |
| homeproxy.upstream                   | Upstream proxy address (host:port); empty means direct connections                                              |               |
| homeproxy.upstream.username          | Username for authenticating against the upstream proxy                                                          |               |
| homeproxy.upstream.password          | Password for authenticating against the upstream proxy                                                          |               |
| homeproxy.bypass                     | Hosts that bypass the upstream proxy and are exempt from the private-network guard; exact host or *.suffix      |               |
| homeproxy.pac.mode                   | PAC routing mode: direct proxies only homeproxy.pac.proxy-hosts, proxy exempts only homeproxy.pac.direct        | direct        |
| homeproxy.pac.proxy-hosts            | Hosts the generated PAC file sends through the proxy in direct mode; exact host or *.suffix                     |               |
| homeproxy.pac.direct                 | Hosts the generated PAC file sends direct; exact host or *.suffix                                               |               |
| homeproxy.pac.proxy                  | Address the generated PAC file names as the proxy, as host:port; empty uses the request Host and homeproxy.port |               |
| homeproxy.pac.require-trusted-client | Serve the PAC file only to addresses in homeproxy.trusted-clients                                               | true          |
| homeproxy.trusted-clients            | Client addresses that use the proxy without a credential, as IPv4/IPv6 addresses or CIDRs                       |               |
| homeproxy.dial-timeout-seconds       | Timeout in seconds for dialling a target or upstream, including the upstream CONNECT handshake                  | 10            |
| server.port                          | Port of the miso management server                                                                              | 7990          |