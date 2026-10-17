package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/curtisnewbie/miso/miso"
)

const (
	propProxyPort          = "homeproxy.port"
	propCredentials        = "homeproxy.users"
	propUpstream           = "homeproxy.upstream"
	propUpstreamUsername   = "homeproxy.upstream.username"
	propUpstreamPassword   = "homeproxy.upstream.password"
	propBypass             = "homeproxy.bypass"
	propDialTimeoutSeconds = "homeproxy.dial-timeout-seconds"

	defaultProxyPort       = 17890
	defaultManagementPort  = 7990
	defaultDialTimeoutSecs = 10
)

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

func init() {
	miso.SetDefProp(propProxyPort, defaultProxyPort)
	miso.SetDefProp(propDialTimeoutSeconds, defaultDialTimeoutSecs)
	miso.SetDefProp(miso.PropServerPort, defaultManagementPort)
}

func Load() (Config, error) {
	cfg := Config{
		ProxyPort:        miso.GetPropInt(propProxyPort),
		ManagementPort:   miso.GetPropInt(miso.PropServerPort),
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
