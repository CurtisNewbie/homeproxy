# 11: iOS app reports a network failure through the proxy

**Status:** wontfix

**Observed:** Xiaohongshu on the iPhone reports a network error while Chrome reaches `bing.com`
normally in the same session. homeproxy's log shows established tunnels with no response bytes for
some targets (`target=api.twitter.com:443 up=517 down=0 duration=16.1s`) next to healthy ones
(`lng.xiaohongshu.com` `down=6488`). That instance had `homeproxy.upstream` commented out, so
every line read `egress=direct bypass=false`.

**Split test:** the same app fails when the iOS Wi-Fi proxy points directly at Clash
(`127.0.0.1:7897`) with homeproxy out of the path. The failure therefore exists without homeproxy
and is not a defect in this service.

**Probe results (Mac, through the live direct-egress proxy):** `www.xiaohongshu.com` 302,
`edith.xiaohongshu.com` 200, `lng.xiaohongshu.com` 200, all under 0.2 s and identical to direct
requests. `sns.xiaohongshu.com` does not resolve at all, direct or proxied. This Mac has no working
IPv6 route; the proxy tries the IPv6 addresses first, gets an immediate "no route", and succeeds on
IPv4.

**Reopen when** the app's own failing request can be identified: reproduce at
`logging.level=debug` and show the `xiaohongshu`/`xhscdn` lines, or show the app working with the
proxy off but failing with both Clash and homeproxy. A failure that survives with the proxy removed
belongs to the app or its network route, not to homeproxy.

**Diagnostic note:** auth challenges are logged at debug level since ticket 10, so a default-level
run no longer shows `proxy auth failed`; use `logging.level=debug` when collecting evidence.
