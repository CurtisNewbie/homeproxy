package config

import (
	"errors"
	"fmt"
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
	if c.ProxyPort == c.ManagementPort {
		return fmt.Errorf("homeproxy.port and server.port must differ, both are %d", c.ProxyPort)
	}
	return nil
}
