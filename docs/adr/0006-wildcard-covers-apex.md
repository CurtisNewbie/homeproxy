# A wildcard host entry covers its own apex

A `*.suffix` entry matched subdomains only. An operator who wanted a whole domain — the bare host
and everything under it — wrote the pair: `example.com` and `*.example.com`. Two entries for one
intent, in every list that had to carry it, and the pair is easy to half-write: leaving out the bare
host silently narrows the rule to subdomains, which is rarely what was meant and hard to notice
until a request takes the wrong egress or the PAC file answers the wrong way.

So a `*.suffix` entry now covers the bare suffix as well as its subdomains: `*.example.com` matches
`example.com` and `api.example.com`. The rule is one way only — an exact entry matches its named
host and nothing under it — so `example.com` and `*.example.com` keep distinct meanings and a list
may hold both without conflict.

The rule lives in one place per matcher and in the generated PAC body, so the server and the client
give the same answer for every host a phone can ask about: the body normalizes what a PAC `host`
argument carries — case, an IPv6 bracket pair, a trailing dot — and the server's wider authority
parsing adds only forms a client never sends. It applies to every host list at once:
`homeproxy.bypass`, `homeproxy.pac.proxy-hosts` and `homeproxy.pac.direct`. Leaving one list strict
would mean two contradictory readings of the same syntax in one binary.

The trade: nothing expresses "subdomains only, leave the apex out" any more. That is deliberate. The
strict form is what forced the duplicate pairs, it shares syntax with the rule operators actually
want, and no shipped config relies on the distinction — the sample lists name domains whose apexes
belong in the rule anyway. An operator who needs the old behaviour lists the subdomains they want
individually.

Rejected: a second wildcard form that keeps both meanings. It buys back a distinction almost nobody
uses, at the cost of two near-identical prefixes that are easy to confuse — the exact failure this
change removes. Also rejected: making an exact entry cover the subtree too. That would leave no way
to name a single host, and it renames the meaning of every exact entry already configured.