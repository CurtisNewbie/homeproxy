package config

import (
	"strings"
	"testing"
)

func validTestConfig() Config {
	return Config{
		ProxyPort:      17890,
		ManagementPort: 7990,
		Credentials:    []Credential{{Name: "phone", Secret: "s3cret"}},
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
