# homeproxy keeps one group selected and owns nothing else about clash

A clash-compatible instance keeps resetting its selector group: a config swap or reload puts it back
to whichever member the config lists first, and a dashboard change has no owner either. The only
thing missing is a small authority that keeps one member selected — and that authority needs no
knowledge of clash beyond its controller, one selector name, and one member name.

So homeproxy sets one selector group to one configured member, at startup and again on an interval,
and touches nothing else. It reads the selector, writes only when it has drifted.

Rejected: fetching and swapping the config from homeproxy. That couples the service to one
subscription's payload and token, and needs the clash host's filesystem; refreshing a clash config is
the operator's script, wherever the file lives. Rejected: latency testing and pinning
the fastest node. A `URLTest` group already re-picks continuously, honours a pinned node only while
that node is alive, and the group delay endpoint clears the pin before it tests; a homeproxy picker
would only freeze a choice clash is already making, and would override the configured member this
feature exists to keep.

Two consequences are deliberate. A manual change in a clash dashboard survives at most one interval
— the configured member is the truth, and that is what makes the drift check worth having. And
management stays independent of homeproxy's own egress: enabling it changes no egress, PAC,
listener, or upstream setting, the managed instance need not be homeproxy's upstream, and disabling
it leaves the proxy path untouched.
