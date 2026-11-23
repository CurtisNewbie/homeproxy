package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/curtisnewbie/miso/miso"
)

func validTestConfig() Config {
	return Config{
		ProxyPort:      17890,
		ManagementPort: 7990,
		Credentials:    []Credential{{Name: "phone", Secret: "s3cret"}},
		PACMode:        PACModeDirect,
	}
}

func TestValidateAuthorizationSources(t *testing.T) {
	tests := []struct {
		name           string
		credentials    []Credential
		trustedClients []string
		wantErr        bool
	}{
		{name: "no users one trusted client", trustedClients: []string{"127.0.0.0/8"}},
		{name: "no users no trusted clients", wantErr: true},
		{name: "users set no trusted clients", credentials: []Credential{{Name: "phone", Secret: "s3cret"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.Credentials = tt.credentials
			cfg.TrustedClients = tt.trustedClients
			err := cfg.validate()
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("validate() = nil, want an error")
			}
			for _, key := range []string{"homeproxy.users", "homeproxy.trusted-clients"} {
				if !strings.Contains(err.Error(), key) {
					t.Errorf("error does not name %s: %v", key, err)
				}
			}
		})
	}
}

func TestValidHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "a.com", want: true},
		{host: "A.com", want: true},
		// HostOnly strips the trailing dot and the IPv6 brackets before the check.
		{host: "a.com.", want: true},
		{host: "[::1]", want: true},
		{host: "::1", want: true},
		{host: "bad host", want: false},
		{host: "*", want: false},
		{host: "a*b.com", want: false},
		{host: "-a.com", want: false},
	}

	for _, tt := range tests {
		if got := ValidHost(HostOnly(tt.host)); got != tt.want {
			t.Errorf("ValidHost(HostOnly(%q)) = %t, want %t", tt.host, got, tt.want)
		}
	}
}

func TestValidatePACDirectEntries(t *testing.T) {
	accepted := []string{"a.com:80", "example.com.", "[::1]", "*.a.com"}
	rejected := []string{"*.[::1]:80", "*.::1", "fe80::1%25en0", "*.", "bad host"}

	for _, entry := range accepted {
		cfg := validTestConfig()
		cfg.PACDirect = []string{entry}
		if err := cfg.validate(); err != nil {
			t.Errorf("homeproxy.pac.direct %q rejected: %v", entry, err)
		}
	}

	for _, entry := range rejected {
		cfg := validTestConfig()
		cfg.PACDirect = []string{entry}
		err := cfg.validate()
		if err == nil {
			t.Errorf("homeproxy.pac.direct %q accepted", entry)
			continue
		}
		if !strings.Contains(err.Error(), "homeproxy.pac.direct") || !strings.Contains(err.Error(), entry) {
			t.Errorf("error for %q does not name the entry: %v", entry, err)
		}
	}
}

func TestValidatePACMode(t *testing.T) {
	for _, value := range []string{"direct", "proxy", " DIRECT ", "Proxy"} {
		cfg := validTestConfig()
		cfg.PACMode = value
		if err := cfg.validate(); err != nil {
			t.Errorf("homeproxy.pac.mode %q rejected: %v", value, err)
			continue
		}
		if want := strings.ToLower(strings.TrimSpace(value)); cfg.PACMode != want {
			t.Errorf("homeproxy.pac.mode after validate = %q, want %q", cfg.PACMode, want)
		}
	}

	for _, value := range []string{"", "auto", "proxyy"} {
		cfg := validTestConfig()
		cfg.PACMode = value
		err := cfg.validate()
		if err == nil {
			t.Errorf("homeproxy.pac.mode %q accepted", value)
			continue
		}
		if !strings.Contains(err.Error(), "homeproxy.pac.mode") || !strings.Contains(err.Error(), fmt.Sprintf("%q", value)) {
			t.Errorf("error for %q does not name the key and the value: %v", value, err)
		}
	}
}

func TestValidateUpstreamEgress(t *testing.T) {
	for _, value := range []string{UpstreamEgressAll, UpstreamEgressPAC, "", " PAC "} {
		cfg := validTestConfig()
		cfg.UpstreamEgress = value
		if err := cfg.validate(); err != nil {
			t.Errorf("homeproxy.upstream.egress %q rejected: %v", value, err)
			continue
		}
		want := strings.ToLower(strings.TrimSpace(value))
		if want == "" {
			want = UpstreamEgressAll
		}
		if cfg.UpstreamEgress != want {
			t.Errorf("homeproxy.upstream.egress after validate = %q, want %q", cfg.UpstreamEgress, want)
		}
	}

	for _, value := range []string{"mixed", "proxied"} {
		cfg := validTestConfig()
		cfg.UpstreamEgress = value
		err := cfg.validate()
		if err == nil {
			t.Errorf("homeproxy.upstream.egress %q accepted", value)
			continue
		}
		if !strings.Contains(err.Error(), "homeproxy.upstream.egress") || !strings.Contains(err.Error(), fmt.Sprintf("%q", value)) {
			t.Errorf("error for %q does not name the key and the value: %v", value, err)
		}
		for _, accepted := range []string{UpstreamEgressAll, UpstreamEgressPAC} {
			if !strings.Contains(err.Error(), fmt.Sprintf("%q", accepted)) {
				t.Errorf("error for %q does not name %q: %v", value, accepted, err)
			}
		}
	}
}

func TestLoadUpstreamAddressPrecedence(t *testing.T) {
	// Load validates the whole Config, so every fixture carries the minimum
	// authorization and leaves ports at their registered defaults.
	const authorization = `  trusted-clients: ["127.0.0.1"]`
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name: "nested address only",
			config: `homeproxy:
  upstream:
    address: "nested.example:8080"
` + authorization,
			want: "nested.example:8080",
		},
		{
			name: "deprecated scalar only",
			config: `homeproxy:
  upstream: "scalar.example:8080"
` + authorization,
			want: "scalar.example:8080",
		},
		{
			// A YAML key cannot be both a scalar and a block, so no real file
			// holds both forms literally. The dotted key is a fixture-only way
			// to set both and exercise the precedence rule.
			name: "nested address wins over deprecated scalar",
			config: `homeproxy:
  upstream: "scalar.example:8080"
  upstream.address: "nested.example:8080"
` + authorization,
			want: "nested.example:8080",
		},
		{
			name: "neither leaves an empty address",
			config: `homeproxy:
` + authorization,
			want: "",
		},
		{
			name: "nested address is trimmed",
			config: `homeproxy:
  upstream:
    address: "  spaced.example:8080  "
` + authorization,
			want: "spaced.example:8080",
		},
		{
			name: "deprecated scalar is trimmed",
			config: `homeproxy:
  upstream: "  spaced.example:8080  "
` + authorization,
			want: "spaced.example:8080",
		},
	}

	// Reload replaces the whole config, so cases cannot leak into each other.
	t.Cleanup(func() { _ = miso.ReloadConfigFromStr("{}") })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := miso.ReloadConfigFromStr(tt.config); err != nil {
				t.Fatalf("reload config: %v", err)
			}
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.Upstream != tt.want {
				t.Errorf("Upstream = %q, want %q", cfg.Upstream, tt.want)
			}
		})
	}
}

func TestValidatePACProxyHostsEntries(t *testing.T) {
	accepted := []string{"a.com:80", "example.com.", "[::1]", "*.a.com"}
	rejected := []string{"*.[::1]:80", "*.::1", "fe80::1%25en0", "bad host"}

	for _, entry := range accepted {
		cfg := validTestConfig()
		cfg.PACProxyHosts = []string{entry}
		if err := cfg.validate(); err != nil {
			t.Errorf("homeproxy.pac.proxy-hosts %q rejected: %v", entry, err)
		}
	}

	for _, entry := range rejected {
		cfg := validTestConfig()
		cfg.PACProxyHosts = []string{entry}
		err := cfg.validate()
		if err == nil {
			t.Errorf("homeproxy.pac.proxy-hosts %q accepted", entry)
			continue
		}
		if !strings.Contains(err.Error(), "homeproxy.pac.proxy-hosts") || !strings.Contains(err.Error(), entry) {
			t.Errorf("error for %q does not name the key and the entry: %v", entry, err)
		}
	}
}

func TestValidatePACRequireTrustedClient(t *testing.T) {
	// On with an empty trusted-clients list is legal: the service boots and
	// refuses every PAC fetch, with a warning at construction.
	cfg := validTestConfig()
	cfg.PACRequireTrustedClient = true
	if err := cfg.validate(); err != nil {
		t.Errorf("true with an empty homeproxy.trusted-clients rejected: %v", err)
	}

	cfg.PACRequireTrustedClient = false
	if err := cfg.validate(); err != nil {
		t.Errorf("false rejected: %v", err)
	}
}

func TestValidatePACProxy(t *testing.T) {
	accepted := []string{"example.com:3128"}
	rejected := []string{"example.com:+3128", "example.com:0", "example.com:70000", "example.com"}

	for _, value := range accepted {
		cfg := validTestConfig()
		cfg.PACProxy = value
		if err := cfg.validate(); err != nil {
			t.Errorf("homeproxy.pac.proxy %q rejected: %v", value, err)
		}
	}

	for _, value := range rejected {
		cfg := validTestConfig()
		cfg.PACProxy = value
		err := cfg.validate()
		if err == nil {
			t.Errorf("homeproxy.pac.proxy %q accepted", value)
			continue
		}
		if !strings.Contains(err.Error(), "homeproxy.pac.proxy") || !strings.Contains(err.Error(), value) {
			t.Errorf("error for %q does not name the value: %v", value, err)
		}
	}
}

func TestValidateManagedClash(t *testing.T) {
	enabled := func(c *Config) {
		c.ManagedClashEnabled = true
		c.ManagedClashController = "http://clash.example:9090"
		c.ManagedClashSelector = "proxy"
		c.ManagedClashProxyName = "phone"
		c.ManagedClashInterval = 15 * time.Minute
	}

	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr string
	}{
		{name: "disabled leaves the block unset", modify: func(*Config) {}},
		{name: "disabled permits an empty block with a zero interval", modify: func(c *Config) {
			c.ManagedClashInterval = -time.Minute
		}},
		{name: "enabled with the full block", modify: enabled},
		{name: "enabled with an empty controller", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashController = ""
		}, wantErr: "managed-clash.controller"},
		{name: "enabled with a whitespace controller", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashController = "   "
		}, wantErr: "managed-clash.controller"},
		{name: "enabled with an empty selector", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashSelector = ""
		}, wantErr: "managed-clash.selector"},
		{name: "enabled with a whitespace selector", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashSelector = "  "
		}, wantErr: "managed-clash.selector"},
		{name: "enabled with an empty proxy name", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashProxyName = ""
		}, wantErr: "managed-clash.proxy-name"},
		{name: "enabled with a whitespace proxy name", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashProxyName = " "
		}, wantErr: "managed-clash.proxy-name"},
		{name: "enabled with a zero interval", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashInterval = 0
		}, wantErr: "managed-clash.interval"},
		{name: "enabled with a negative interval", modify: func(c *Config) {
			enabled(c)
			c.ManagedClashInterval = -time.Second
		}, wantErr: "managed-clash.interval"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			tt.modify(&cfg)
			err := cfg.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() = nil, want an error naming %s", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error does not name %s: %v", tt.wantErr, err)
			}
		})
	}
}

func TestLoadManagedClash(t *testing.T) {
	t.Cleanup(func() { _ = miso.ReloadConfigFromStr("{}") })

	t.Run("defaults", func(t *testing.T) {
		if err := miso.ReloadConfigFromStr(`managed-clash:
  enabled: true
  selector: proxy
  proxy-name: phone
homeproxy:
  trusted-clients: ["127.0.0.1"]
`); err != nil {
			t.Fatalf("reload config: %v", err)
		}
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if !cfg.ManagedClashEnabled {
			t.Error("ManagedClashEnabled = false, want true")
		}
		if cfg.ManagedClashController != "http://localhost:9990" {
			t.Errorf("ManagedClashController = %q, want http://localhost:9990", cfg.ManagedClashController)
		}
		if cfg.ManagedClashSecret != "" {
			t.Errorf("ManagedClashSecret = %q, want empty", cfg.ManagedClashSecret)
		}
		if cfg.ManagedClashInterval != 15*time.Minute {
			t.Errorf("ManagedClashInterval = %s, want 15m", cfg.ManagedClashInterval)
		}
	})

	t.Run("names are trimmed", func(t *testing.T) {
		if err := miso.ReloadConfigFromStr(`managed-clash:
  enabled: true
  selector: "  proxy  "
  proxy-name: "  phone  "
homeproxy:
  trusted-clients: ["127.0.0.1"]
`); err != nil {
			t.Fatalf("reload config: %v", err)
		}
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.ManagedClashSelector != "proxy" {
			t.Errorf("ManagedClashSelector = %q, want %q", cfg.ManagedClashSelector, "proxy")
		}
		if cfg.ManagedClashProxyName != "phone" {
			t.Errorf("ManagedClashProxyName = %q, want %q", cfg.ManagedClashProxyName, "phone")
		}
	})

	t.Run("configured interval is honoured", func(t *testing.T) {
		if err := miso.ReloadConfigFromStr(`managed-clash:
  enabled: false
  interval: 90s
homeproxy:
  trusted-clients: ["127.0.0.1"]
`); err != nil {
			t.Fatalf("reload config: %v", err)
		}
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.ManagedClashInterval != 90*time.Second {
			t.Errorf("ManagedClashInterval = %s, want 90s", cfg.ManagedClashInterval)
		}
	})
}
