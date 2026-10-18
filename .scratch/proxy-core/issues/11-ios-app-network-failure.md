# 11: iOS app reports a network failure through the proxy

**Status:** needs-info

**Observed:** Xiaohongshu on the iPhone reports a network error while its traffic goes through
homeproxy, in the same session where Chrome reaches `bing.com` normally. The proxy's log for the
same period shows tunnels that were established (`outcome=ok`) but carried no response bytes, e.g.
`target=api.twitter.com:443 up=517 down=0 duration=16.1s`, alongside normal tunnels
(`down=6488` on `lng.xiaohongshu.com`). The running instance had `homeproxy.upstream` commented
out, so every line carried `egress=direct bypass=false`.

**Why this is not yet a diagnosis:** `outcome=ok` only says the tunnel was opened and later closed
cleanly; `down=0` is consistent with three different failures:

- the direct egress cannot reach the host (ISP-level blocking, blackhole, TLS reset);
- the client app never sent a request over the tunnel, or stopped reading;
- the app's own network stack does not survive the proxy's `407` challenge or does not use the
  system proxy at all.

**Probe results (Mac, through the live direct-egress proxy):** `www.xiaohongshu.com` 302,
`edith.xiaohongshu.com` 200, `lng.xiaohongshu.com` 200, all under 0.2 s; direct requests return the
same statuses. `sns.xiaohongshu.com` does not resolve at all (also fails direct), so it is not a
proxy fault. This Mac has no working IPv6 route; the proxy tries the IPv6 addresses first, gets an
immediate "no route", and succeeds on IPv4.

**Info needed before diagnosing:**

- which app (name, version), and the exact error text shown;
- local time window of the failure, plus whether `homeproxy.upstream` was configured in the
  process that was running then;
- whether Safari/another app worked through the proxy at the same time;
- whether the same app works with Clash set as the iOS proxy directly (bypassing homeproxy);
- whether the app talks to any LAN/private address (those are refused with `403` unless the host
  is in `homeproxy.bypass`);
- whether the phone showed the proxy credential prompt for that app.

**Diagnostic note:** auth challenges are logged at debug level since ticket 10, so a default-level
run no longer shows `proxy auth failed`; run with `logging.level=debug` when collecting evidence.

**Guard rails for the investigation:** no fix before the root cause is confirmed; reproduce with a
real client, then treat the fix as a ticket.
