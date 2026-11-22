# A trusted client address may stand in for a credential

Some clients cannot answer a `407` — the Weibo iOS app reads the system proxy, sends `CONNECT`
without `Proxy-Authorization`, and gives up when challenged. Since no credential can reach such a
client, `homeproxy.trusted-clients` lets a configured address, or a CIDR, skip the credential check
while every other rule stays: the private-network guard still refuses private targets and the
bypass list still decides the egress. The trade is explicit — authority moves from a secret to an
address, so any device that can use a listed address can use the proxy. Keep the entries to networks
the operator controls, and never list a public range that others share. Rejected: an address that
becomes trusted after one successful authentication (a cold start races it, and it widens the blast
radius of a shared public address), and running the port without authentication at all.