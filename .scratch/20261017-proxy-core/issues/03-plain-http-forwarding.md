# 03: Plain-HTTP forwarding, direct egress

**What to build:** Plain `http://` requests work through the proxy, so the same credential covers
both request kinds; proxy-only headers are consumed at the proxy and never reach the target.

**Blocked by:** 02 (credential-gated CONNECT tunnel, direct egress)

**Status:** done

- [x] an absolute-form `GET` through the proxy reaches a local HTTP target and returns its status, headers and body
- [x] an absolute-form `POST` body is forwarded intact
- [x] responses stream rather than buffer: a slow target response is delivered incrementally
- [x] `Proxy-Authorization` and `Proxy-Connection` are not forwarded to the target
- [x] hop-by-hop headers, including those named in `Connection`, are stripped
- [x] a request whose path is not absolute receives `400`
- [x] an unauthenticated absolute-form request receives the 407 challenge, not a forward
