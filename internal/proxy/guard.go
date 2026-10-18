package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// resolutionTTL is how long a host's resolved addresses are reused. It is short
// on purpose: it spares the lookup per request, not a changed DNS record.
const resolutionTTL = 30 * time.Second

// errGuardRefused marks a target the private-network guard refuses to reach. It
// is distinct from a dial or lookup failure: the proxy answered 403 without
// dialling anything.
var errGuardRefused = errors.New("target refused by private-network guard")

// resolver resolves target hosts to addresses, caching each result briefly so a
// connection does not pay a lookup per request.
type resolver struct {
	ttl     time.Duration
	lookup  func(ctx context.Context, host string) ([]net.IPAddr, error)
	mu      sync.Mutex
	entries map[string]resolution
}

type resolution struct {
	addresses []net.IPAddr
	err       error
	expires   time.Time
}

func newResolver() *resolver {
	return &resolver{
		ttl:     resolutionTTL,
		lookup:  net.DefaultResolver.LookupIPAddr,
		entries: make(map[string]resolution),
	}
}

// resolve returns the addresses host resolves to. Both a successful and a failed
// lookup are cached for the TTL; a failure is returned as an error.
func (r *resolver) resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	entry, ok := r.entries[host]
	r.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.addresses, entry.err
	}

	addresses, err := r.lookup(ctx, host)
	if err == nil && len(addresses) == 0 {
		err = fmt.Errorf("host %s resolved to no address", host)
	}

	r.mu.Lock()
	r.entries[host] = resolution{addresses: addresses, err: err, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()

	return addresses, err
}

// cgnat is 100.64.0.0/10, the carrier-grade NAT range net.IP does not classify.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// nonPublic reports whether ip is an address the proxy must not reach unless the
// host is listed in homeproxy.bypass: loopback, RFC1918 or IPv6 unique-local,
// link-local (which includes the cloud metadata address 169.254.169.254), CGNAT,
// multicast and the unspecified address. IPv4-mapped IPv6 addresses are judged as
// the IPv4 address they carry.
func nonPublic(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() ||
		cgnat.Contains(ip)
}
