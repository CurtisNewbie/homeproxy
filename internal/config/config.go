package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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

	// misoconfig-prop: Hosts the generated PAC file sends direct; exact host or *.suffix
	propPACDirect = "homeproxy.pac.direct"

	// misoconfig-prop: Address the generated PAC file names as the proxy, as host:port; empty uses the request Host and homeproxy.port
	propPACProxy = "homeproxy.pac.proxy"

	// misoconfig-prop: Serve the PAC file only to addresses in homeproxy.trusted-clients | true
	propPACRequireTrustedClient = "homeproxy.pac.require-trusted-client"

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
	miso.SetDefProp(propPACRequireTrustedClient, true)
	miso.SetDefProp(propDialTimeoutSeconds, 10)
	miso.SetDefProp(propManagementPort, 7990)
}

// misoconfig-default-end

type Credential struct {
	Name   string
	Secret string
}

type Config struct {
	ProxyPort               int
	ManagementPort          int
	Credentials             []Credential
	Upstream                string
	UpstreamUsername        string
	UpstreamPassword        string
	Bypass                  []string
	PACDirect               []string
	PACProxy                string
	PACRequireTrustedClient bool
	TrustedClients          []string
	DialTimeout             time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		ProxyPort:               miso.GetPropInt(propProxyPort),
		ManagementPort:          miso.GetPropInt(propManagementPort),
		Credentials:             miso.UnmarshalFromPropKeyAs[[]Credential](propCredentials),
		Upstream:                miso.GetPropStr(propUpstream),
		UpstreamUsername:        miso.GetPropStr(propUpstreamUsername),
		UpstreamPassword:        miso.GetPropStr(propUpstreamPassword),
		Bypass:                  miso.GetPropStrSlice(propBypass),
		PACDirect:               miso.GetPropStrSlice(propPACDirect),
		PACProxy:                miso.GetPropStr(propPACProxy),
		PACRequireTrustedClient: miso.GetPropBool(propPACRequireTrustedClient),
		TrustedClients:          miso.GetPropStrSlice(propTrustedClients),
		DialTimeout:             time.Duration(miso.GetPropInt(propDialTimeoutSeconds)) * time.Second,
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
	for i, entry := range c.PACDirect {
		if !validPACDirect(entry) {
			return fmt.Errorf("homeproxy.pac.direct entry %d %q must be a hostname or IP literal, optionally *. prefixed", i, entry)
		}
	}
	if c.PACProxy != "" {
		host, port, err := net.SplitHostPort(c.PACProxy)
		if err != nil || host == "" || !ValidHost(host) {
			return fmt.Errorf("homeproxy.pac.proxy %q must be host:port with a hostname or IP literal host", c.PACProxy)
		}
		number, err := strconv.Atoi(port)
		if err != nil || !allDigits(port) || number < 1 || number > 65535 {
			return fmt.Errorf("homeproxy.pac.proxy %q must have a port in 1-65535", c.PACProxy)
		}
	}
	if c.ProxyPort == c.ManagementPort {
		return fmt.Errorf("homeproxy.port and server.port must differ, both are %d", c.ProxyPort)
	}
	return nil
}

// ValidHost reports whether host is a hostname or IP literal, the form HostOnly
// leaves a PAC entry or a request Host in: no brackets.
func ValidHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return validHostname(host)
}

// validPACDirect reports whether entry is a host newBypassList can match: the
// same HostOnly normalization, then an optional "*." denoting subdomains.
func validPACDirect(entry string) bool {
	host := HostOnly(entry)
	suffix, wildcard := strings.CutPrefix(host, "*.")
	if !ValidHost(suffix) {
		return false
	}
	if addr, err := netip.ParseAddr(suffix); err == nil {
		// An IP literal matches exactly; a *. prefix or a zone can never match a
		// PAC host, which carries neither.
		return !wildcard && addr.Zone() == ""
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// HostOnly reduces an authority to the comparable part of a host name: no port,
// no IPv6 brackets, no trailing dot, lowercase.
func HostOnly(authority string) string {
	authority = strings.TrimSpace(authority)
	if host, _, err := net.SplitHostPort(authority); err == nil {
		authority = host
	}
	authority = strings.TrimPrefix(authority, "[")
	authority = strings.TrimSuffix(authority, "]")
	authority = strings.TrimSuffix(authority, ".")
	return strings.ToLower(authority)
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
