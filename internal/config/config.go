package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/curtisnewbie/miso/miso"
)

// misoconfig-section: Home Proxy Configuration
const (
	// misoconfig-prop: Port on which the forward HTTP proxy listens | 17890
	propProxyPort = "homeproxy.port"

	// misoconfig-prop: Basic auth credentials allowed to use the proxy, as a list of name/secret entries
	propCredentials = "homeproxy.users"

	// misoconfig-prop: Upstream proxy address (host:port); empty means direct connections
	propUpstream = "homeproxy.upstream"

	// misoconfig-prop: Username for authenticating against the upstream proxy
	propUpstreamUsername = "homeproxy.upstream.username"

	// misoconfig-prop: Password for authenticating against the upstream proxy
	propUpstreamPassword = "homeproxy.upstream.password"

	// misoconfig-prop: Hosts that bypass the upstream proxy and are exempt from the private-network guard; exact host or *.suffix
	propBypass = "homeproxy.bypass"

	// misoconfig-prop: Client addresses that use the proxy without a credential, as IPv4/IPv6 addresses or CIDRs
	propTrustedClients = "homeproxy.trusted-clients"

	// misoconfig-prop: Timeout in seconds for dialling a target or upstream, including the upstream CONNECT handshake | 10
	propDialTimeoutSeconds = "homeproxy.dial-timeout-seconds"

	// misoconfig-prop: Port of the miso management server | 7990
	propManagementPort = "server.port"
)

// misoconfig-default-start
func init() {
	miso.SetDefProp(propProxyPort, 17890)
	miso.SetDefProp(propDialTimeoutSeconds, 10)
	miso.SetDefProp(propManagementPort, 7990)
}

// misoconfig-default-end

type Credential struct {
	Name   string
	Secret string
}

type Config struct {
	ProxyPort        int
	ManagementPort   int
	Credentials      []Credential
	Upstream         string
	UpstreamUsername string
	UpstreamPassword string
	Bypass           []string
	TrustedClients   []string
	DialTimeout      time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		ProxyPort:        miso.GetPropInt(propProxyPort),
		ManagementPort:   miso.GetPropInt(propManagementPort),
		Credentials:      miso.UnmarshalFromPropKeyAs[[]Credential](propCredentials),
		Upstream:         miso.GetPropStr(propUpstream),
		UpstreamUsername: miso.GetPropStr(propUpstreamUsername),
		UpstreamPassword: miso.GetPropStr(propUpstreamPassword),
		Bypass:           miso.GetPropStrSlice(propBypass),
		TrustedClients:   miso.GetPropStrSlice(propTrustedClients),
		DialTimeout:      time.Duration(miso.GetPropInt(propDialTimeoutSeconds)) * time.Second,
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.ProxyPort <= 0 {
		return fmt.Errorf("homeproxy.port must be a positive port, got %d", c.ProxyPort)
	}
	if c.ManagementPort <= 0 {
		return fmt.Errorf("server.port must be a positive port, got %d", c.ManagementPort)
	}
	if len(c.Credentials) == 0 {
		return errors.New("homeproxy.users must contain at least one credential")
	}
	for i, cred := range c.Credentials {
		if cred.Name == "" || cred.Secret == "" {
			return fmt.Errorf("homeproxy.users entry %d must have both name and secret", i)
		}
	}
	if _, err := ParseTrustedClients(c.TrustedClients); err != nil {
		return err
	}
	if c.ProxyPort == c.ManagementPort {
		return fmt.Errorf("homeproxy.port and server.port must differ, both are %d", c.ProxyPort)
	}
	return nil
}

// ParseTrustedClients parses homeproxy.trusted-clients into the prefixes a client
// address is matched against. A bare address becomes a single-address prefix, and
// an entry that trusts every address is refused.
func ParseTrustedClients(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		prefix, err := parseTrustedClient(entry)
		if err != nil {
			return nil, fmt.Errorf("homeproxy.trusted-clients entry %d %q is not a valid address or CIDR: %w", i, entry, err)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("homeproxy.trusted-clients entry %d %q is an IPv4-mapped prefix narrower than /96; write the IPv4 CIDR instead", i, entry)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("homeproxy.trusted-clients entry %d %q must not trust every address", i, entry)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseTrustedClient(entry string) (netip.Prefix, error) {
	if strings.Contains(entry, "/") {
		return netip.ParsePrefix(entry)
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
