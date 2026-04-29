package dialer

import (
	"testing"
)

func TestBypassPatternMatches(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		port    string
		want    bool
	}{
		{"192.168.1.1", "192.168.1.1", "443", true},
		{"192.168.1.1", "192.168.1.2", "443", false},
		{"192.168.0.0/16", "192.168.1.100", "80", true},
		{"192.168.0.0/16", "10.0.0.1", "80", false},
		{"192.168.0.0/24:443", "192.168.0.5", "443", true},
		{"192.168.0.0/24:443", "192.168.0.5", "80", false},
		{"192.168.0.0/24:443", "10.0.0.1", "443", false},
		{"example.com", "example.com", "443", true},
		{"example.com", "sub.example.com", "443", false},
		{"Example.COM", "example.com", "80", true},
		{"*.example.com", "sub.example.com", "443", true},
		{"*.example.com", "deep.sub.example.com", "443", true},
		{"*.example.com", "example.com", "443", false},
		{"*.example.com", "notexample.com", "443", false},
		{"localhost:8080", "localhost", "8080", true},
		{"localhost:8080", "localhost", "9090", false},
		{"example.com", "example.com", "", true},
		{"example.com", "example.com", "8080", true},
		// TLD wildcard: only matches subdomains, not the TLD itself
		{"*.ru", "yandex.ru", "443", true},
		{"*.ru", "www.yandex.ru", "443", true},
		{"*.ru", "ru", "443", false},
		// Exact domain
		{"yandex.ru", "yandex.ru", "80", true},
		{"yandex.ru", "www.yandex.ru", "80", false},
	}

	for _, tc := range cases {
		p, err := parseBypassPattern(tc.pattern)
		if err != nil {
			t.Errorf("parseBypassPattern(%q) error: %v", tc.pattern, err)
			continue
		}
		got := p.matches(tc.host, tc.port)
		if got != tc.want {
			t.Errorf("pattern=%q host=%q port=%q: got %v, want %v",
				tc.pattern, tc.host, tc.port, got, tc.want)
		}
	}
}

func TestShouldBypass(t *testing.T) {
	bd, err := NewBypassDialer(
		[]string{"192.168.0.0/24", "*.internal", "exact.host:8080"},
		nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		addr string
		want bool
	}{
		{"192.168.0.1:443", true},
		{"192.168.1.1:443", false},
		{"foo.internal:443", true},
		{"internal:443", false},
		{"exact.host:8080", true},
		{"exact.host:9090", false},
		{"google.com:443", false},
	}

	for _, tc := range cases {
		got, _ := bd.shouldBypass(tc.addr)
		if got != tc.want {
			t.Errorf("shouldBypass(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestParseBypassPatternErrors(t *testing.T) {
	bad := []string{
		"",
		"192.168.0.0/999",
		"**.example.com",
		"*.*.example.com",
	}
	for _, raw := range bad {
		_, err := parseBypassPattern(raw)
		if err == nil {
			t.Errorf("parseBypassPattern(%q) expected error, got nil", raw)
		}
	}
}

func TestTLDWildcardSkippedInResolve(t *testing.T) {
	// *.ru should still match hostnames even though resolution is skipped
	bd, err := NewBypassDialer([]string{"*.ru"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := bd.shouldBypass("yandex.ru:443")
	if !got {
		t.Error("*.ru should match yandex.ru:443 via hostname matching")
	}
	got, _ = bd.shouldBypass("ru:443")
	if got {
		t.Error("*.ru should NOT match bare 'ru'")
	}
}
