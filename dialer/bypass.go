package dialer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// BypassDialer routes connections based on the destination address:
//   - addresses matching any bypass pattern go directly (via directDialer)
//   - all other addresses go through the proxy (via proxyDialer)
//
// Supported pattern formats (case-insensitive):
//
//	192.168.1.1           — exact IP (any port)
//	192.168.0.0/16        — CIDR block (any port)
//	example.com           — exact hostname (any port)
//	*.example.com         — wildcard: any subdomain
//	localhost:8080        — hostname + specific port
//	192.168.1.1:443       — IP + specific port
//	192.168.0.0/24:443    — CIDR + specific port
//
// SOCKS5 + DNS note:
// When used in SOCKS5 mode, hostname patterns only match if the SOCKS client
// sends the hostname directly (ATYP=0x03 / SOCKS5h mode). Most clients resolve
// DNS themselves and send an IP address (ATYP=0x01) — in that case only CIDR
// rules match. Call ResolvePatterns() once after construction to pre-resolve
// hostnames into CIDRs so IP-based bypass works correctly.
type BypassDialer struct {
	mu           sync.RWMutex
	patterns     []bypassPattern
	directDialer ContextDialer
	proxyDialer  ContextDialer
	logger       bypassLogger
}

// bypassLogger matches the signature of *clog.CondLogger so it can be passed
// directly without an adapter.
type bypassLogger interface {
	Info(fmt string, args ...interface{}) error
	Debug(fmt string, args ...interface{}) error
}

// noopLogger silently discards all log messages.
type noopLogger struct{}

func (noopLogger) Info(string, ...interface{}) error  { return nil }
func (noopLogger) Debug(string, ...interface{}) error { return nil }

type bypassPattern struct {
	raw      string
	port     string      // "" = any port
	hostKind patternKind
	cidr     *net.IPNet // kindCIDR
	host     string     // kindExact | kindWildcard
}

type patternKind int

const (
	kindExact    patternKind = iota
	kindWildcard             // *.suffix
	kindCIDR
)

// NewBypassDialer compiles patterns and returns a BypassDialer.
// logger may be nil (logging disabled).
func NewBypassDialer(patterns []string, directDialer, proxyDialer ContextDialer, logger bypassLogger) (*BypassDialer, error) {
	if logger == nil {
		logger = noopLogger{}
	}
	compiled := make([]bypassPattern, 0, len(patterns))
	for _, raw := range patterns {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := parseBypassPattern(raw)
		if err != nil {
			return nil, fmt.Errorf("bypass pattern %q: %w", raw, err)
		}
		compiled = append(compiled, p)
	}
	return &BypassDialer{
		patterns:     compiled,
		directDialer: directDialer,
		proxyDialer:  proxyDialer,
		logger:       logger,
	}, nil
}

// ResolvePatterns pre-resolves hostname and wildcard patterns into their IP
// addresses and adds them as CIDR /32 (or /128) rules. This is needed when
// the SOCKS5 client resolves DNS itself and sends IP addresses.
//
// resolver is the DNS function to use. Pass nil to use net.DefaultResolver.
// On Android with CGO disabled, net.DefaultResolver may fail because Go's
// pure-Go resolver reads /etc/resolv.conf which may not exist. In that case
// pass a custom resolver backed by the bootstrap DNS already configured in
// the proxy (see buildCustomResolver in main.go).
//
// Wildcard TLD patterns (e.g. *.ru) are skipped — resolving a TLD returns
// nothing useful. List specific domains instead (e.g. yandex.ru, *.yandex.ru).
//
// The resolved IPs supplement the original patterns; hostname matching
// continues to work for clients that send hostnames.
func (bd *BypassDialer) ResolvePatterns(ctx context.Context, resolver *net.Resolver) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	// Snapshot current patterns so we don't iterate over appended results.
	bd.mu.RLock()
	snapshot := make([]bypassPattern, len(bd.patterns))
	copy(snapshot, bd.patterns)
	bd.mu.RUnlock()

	var newPatterns []bypassPattern
	for _, p := range snapshot {
		if p.hostKind != kindExact && p.hostKind != kindWildcard {
			continue // CIDR patterns need no resolution
		}
		if net.ParseIP(p.host) != nil {
			continue // already an IP literal
		}

		hostname := p.host
		if p.hostKind == kindWildcard {
			// p.host = ".example.com" — strip leading dot to get the apex
			hostname = strings.TrimPrefix(p.host, ".")

			// Skip TLD-only wildcards like "*.ru" — resolving "ru" yields
			// nothing meaningful and pollutes the pattern list.
			if !strings.Contains(hostname, ".") {
				bd.logger.Debug("bypass: skipping TLD wildcard %q (use exact domains instead)", p.raw)
				continue
			}
		}

		ips, err := resolver.LookupIPAddr(ctx, hostname)
		if err != nil {
			bd.logger.Info("bypass: resolve %q failed: %v (hostname-only matching)", hostname, err)
			continue
		}
		for _, ia := range ips {
			bits := 32
			if ia.IP.To4() == nil {
				bits = 128
			}
			_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ia.IP.String(), bits))
			if err != nil {
				continue
			}
			newPatterns = append(newPatterns, bypassPattern{
				raw:      fmt.Sprintf("resolved:%s→%s", hostname, ia.IP),
				port:     p.port,
				hostKind: kindCIDR,
				cidr:     cidr,
			})
			bd.logger.Debug("bypass: resolved %q → %s", hostname, ia.IP)
		}
	}

	if len(newPatterns) > 0 {
		bd.mu.Lock()
		bd.patterns = append(bd.patterns, newPatterns...)
		bd.mu.Unlock()
		bd.logger.Info("bypass: pre-resolved %d IP(s) from hostname patterns (total rules: %d)",
			len(newPatterns), len(bd.patterns))
	}
}

func parseBypassPattern(raw string) (bypassPattern, error) {
	if raw == "" {
		return bypassPattern{}, fmt.Errorf("empty pattern")
	}

	p := bypassPattern{raw: raw}
	hostPart := raw

	if strings.HasPrefix(raw, "[") {
		// IPv6 bracket notation: [::1]:443
		h, port, err := net.SplitHostPort(raw)
		if err != nil {
			return p, fmt.Errorf("invalid bracketed address: %w", err)
		}
		p.port = port
		p.hostKind = kindExact
		p.host = strings.ToLower(h)
		return p, nil
	}

	colonCount := strings.Count(raw, ":")
	if colonCount > 1 {
		// Bare IPv6, no port
		hostPart = raw
	} else if colonCount == 1 {
		lastColon := strings.LastIndex(raw, ":")
		possiblePort := raw[lastColon+1:]
		if isValidPort(possiblePort) {
			hostPart = raw[:lastColon]
			p.port = possiblePort
		}
	}

	hostPart = strings.ToLower(hostPart)

	// CIDR?
	if strings.Contains(hostPart, "/") {
		_, cidr, err := net.ParseCIDR(hostPart)
		if err != nil {
			return p, fmt.Errorf("invalid CIDR %q: %w", hostPart, err)
		}
		p.hostKind = kindCIDR
		p.cidr = cidr
		return p, nil
	}

	// Wildcard hostname?
	if strings.HasPrefix(hostPart, "*.") {
		suffix := hostPart[1:] // ".example.com"
		if strings.ContainsAny(suffix, "*?") {
			return p, fmt.Errorf("only leading wildcard (*.) is supported")
		}
		p.hostKind = kindWildcard
		p.host = suffix
		return p, nil
	}

	// Exact hostname or IP literal
	p.hostKind = kindExact
	p.host = hostPart
	return p, nil
}

func (p bypassPattern) matches(host, port string) bool {
	if p.port != "" && p.port != port {
		return false
	}
	host = strings.ToLower(host)
	switch p.hostKind {
	case kindCIDR:
		ip := net.ParseIP(host)
		return ip != nil && p.cidr.Contains(ip)
	case kindWildcard:
		// p.host = ".example.com"
		return strings.HasSuffix(host, p.host) && len(host) > len(p.host)
	case kindExact:
		if host == p.host {
			return true
		}
		// IP literal comparison (normalises IPv4-mapped IPv6 etc.)
		if ip := net.ParseIP(host); ip != nil {
			if pip := net.ParseIP(p.host); pip != nil {
				return ip.Equal(pip)
			}
		}
	}
	return false
}

func (bd *BypassDialer) shouldBypass(addr string) (bool, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}
	host = strings.Trim(host, "[]")

	bd.mu.RLock()
	defer bd.mu.RUnlock()
	for _, p := range bd.patterns {
		if p.matches(host, port) {
			return true, p.raw
		}
	}
	return false, ""
}

func (bd *BypassDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	bypass, matchedRule := bd.shouldBypass(addr)
	if bypass {
		bd.logger.Debug("bypass: DIRECT  %s (rule: %s)", addr, matchedRule)
		return bd.directDialer.DialContext(ctx, network, addr)
	}
	bd.logger.Debug("bypass: PROXY   %s", addr)
	return bd.proxyDialer.DialContext(ctx, network, addr)
}

func (bd *BypassDialer) Dial(network, addr string) (net.Conn, error) {
	return bd.DialContext(context.Background(), network, addr)
}

// LoadBypassFile reads bypass patterns from a text file.
// Empty lines and lines starting with # are ignored.
// Inline comments (preceded by whitespace + #) are stripped.
// Windows line endings (\r\n) are handled transparently by bufio.Scanner.
func LoadBypassFile(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comment: " # comment"
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			patterns = append(patterns, line)
		}
	}
	return patterns, sc.Err()
}

func isValidPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > 0 && n <= 65535
}
