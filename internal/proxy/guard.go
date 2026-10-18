package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// resolutionTTL is how long a successful lookup is reused. It is short on
	// purpose: it spares the lookup per request, not a changed DNS record.
	resolutionTTL = 30 * time.Second
	// resolutionFailureTTL is shorter so one transient failure does not hide a
	// host for a whole success TTL.
	resolutionFailureTTL = 5 * time.Second
	// resolverMaxEntries bounds the cache, whose keys come from client requests.
	resolverMaxEntries = 4096
)

// errGuardRefused marks a target the private-network guard refuses to reach. It
// is distinct from a dial or lookup failure: the proxy answered 403 without
// dialling anything.
var errGuardRefused = errors.New("target refused by private-network guard")

// resolver resolves target hosts to addresses, caching each result briefly so a
// connection does not pay a lookup per request.
type resolver struct {
	ttl        time.Duration
	failureTTL time.Duration
	lookup     func(ctx context.Context, host string) ([]net.IPAddr, error)
	mu         sync.Mutex
	entries    map[string]resolution
}

type resolution struct {
	addresses []net.IPAddr
	err       error
	expires   time.Time
}

func newResolver() *resolver {
	return &resolver{
		ttl:        resolutionTTL,
		failureTTL: resolutionFailureTTL,
		lookup:     net.DefaultResolver.LookupIPAddr,
		entries:    make(map[string]resolution),
	}
}

// resolve returns the addresses host resolves to. A successful lookup is cached
// for the success TTL, a failed one for the shorter failure TTL; a failure is
// returned as an error.
func (r *resolver) resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	now := time.Now()
	r.mu.Lock()
	entry, ok := r.entries[host]
	r.mu.Unlock()
	if ok && now.Before(entry.expires) {
		return entry.addresses, entry.err
	}

	addresses, err := r.lookup(ctx, host)
	if err == nil && len(addresses) == 0 {
		err = fmt.Errorf("host %s resolved to no address", host)
	}
	ttl := r.ttl
	if err != nil {
		ttl = r.failureTTL
	}

	stored := time.Now()
	r.mu.Lock()
	r.storeLocked(host, resolution{addresses: addresses, err: err, expires: stored.Add(ttl)}, stored)
	r.mu.Unlock()

	return addresses, err
}

// storeLocked inserts a resolution, sweeping expired entries once the cache is
// full and evicting one live entry if it is still full. Keys come from
// client-controlled targets, so the map must not grow without bound.
func (r *resolver) storeLocked(host string, res resolution, now time.Time) {
	if _, exists := r.entries[host]; !exists && len(r.entries) >= resolverMaxEntries {
		for key, entry := range r.entries {
			if !now.Before(entry.expires) {
				delete(r.entries, key)
			}
		}
		if len(r.entries) >= resolverMaxEntries {
			for key := range r.entries {
				delete(r.entries, key)
				break
			}
		}
	}
	r.entries[host] = res
}

var (
	// cgnat is 100.64.0.0/10, the carrier-grade NAT range net.IP does not classify.
	cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	// thisNetwork is 0.0.0.0/8; net.IP classifies only the single unspecified address.
	thisNetwork = &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
	// benchmarking is 198.18.0.0/15, reserved for network benchmarking.
	benchmarking = &net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}
	// reserved is 240.0.0.0/4, which includes the broadcast address.
	reserved = &net.IPNet{IP: net.IPv4(240, 0, 0, 0), Mask: net.CIDRMask(4, 32)}
)

// nonPublic reports whether ip is an address the proxy must not reach unless the
// host is listed in homeproxy.bypass: loopback, RFC1918 or IPv6 unique-local,
// link-local (which includes the cloud metadata address 169.254.169.254), CGNAT,
// multicast, the unspecified address, IPv4 0.0.0.0/8, benchmarking
// 198.18.0.0/15 and reserved 240.0.0.0/4. IPv4-mapped IPv6 addresses are judged
// as the IPv4 address they carry.
func nonPublic(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() ||
		thisNetwork.Contains(ip) ||
		cgnat.Contains(ip) ||
		benchmarking.Contains(ip) ||
		reserved.Contains(ip)
}
