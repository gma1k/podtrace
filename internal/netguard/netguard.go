// Package netguard hardens outbound HTTP made on behalf of tenant-supplied
// exporter endpoints.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/netguard/blocklist"
)

var ErrBlocked = errors.New("blocked by the egress guard")

// IsBlockedIP reports whether ip is an address an exporter must never connect
// to: everything blocklist.IsBlocked refuses, plus the private ranges when
// the operator opted into blocking them.
func IsBlockedIP(ip net.IP) bool {
	if blocklist.IsBlocked(ip) {
		return true
	}
	if !config.ExporterBlockPrivateRanges() {
		return false
	}
	if v4 := blocklist.EmbeddedIPv4(ip); v4 != nil {
		ip = v4
	}
	return ip.IsPrivate()
}

// ValidateEndpointHost rejects an endpoint whose host is a literal IP an
// exporter must never reach.
func ValidateEndpointHost(host string) error {
	if ip := net.ParseIP(host); ip != nil && IsBlockedIP(ip) {
		return fmt.Errorf("endpoint host %q is a blocked address (link-local/metadata): %w", host, ErrBlocked)
	}
	return nil
}

// controlBlockSSRF is a net.Dialer.Control hook.
func controlBlockSSRF(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || IsBlockedIP(ip) {
		return fmt.Errorf("netguard: refusing exporter connection to blocked address %q: %w", address, ErrBlocked)
	}
	return nil
}

// controlBlockAlways is the dial hook for the configured egress proxy: it
// refuses only what no connection may reach (link-local, metadata), not the
// private ranges, because the proxy is set by whoever runs podtrace and
// commonly sits on a private address. The proxied target is still checked
// against the private ranges by guardedProxy.
func controlBlockAlways(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || blocklist.IsBlocked(ip) {
		return fmt.Errorf("netguard: refusing proxy connection to blocked address %q: %w", address, ErrBlocked)
	}
	return nil
}

// isEgressProxyAddress reports whether addr, as the transport dials it, is
// the configured egress proxy: the PODTRACE_EGRESS_* proxy when set,
// otherwise the standard HTTP_PROXY/HTTPS_PROXY.
func isEgressProxyAddress(addr string) bool {
	p := config.EgressProxySettings()
	if !p.Set() {
		env := httpproxy.FromEnvironment()
		p = config.EgressProxy{HTTPProxy: env.HTTPProxy, HTTPSProxy: env.HTTPSProxy}
	}
	addr = strings.ToLower(addr)
	for _, raw := range []string{p.HTTPProxy, p.HTTPSProxy} {
		if a := proxyDialAddress(raw); a != "" && a == addr {
			return true
		}
	}
	return false
}

// proxyDialAddress is the host:port the transport dials for a proxy URL,
// with the scheme's default port, matching how net/http resolves it.
func proxyDialAddress(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if u, err = url.Parse("http://" + raw); err != nil || u.Host == "" {
			return ""
		}
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// dialGuarded dials with the SSRF guard, relaxing only the private-range
// check for the configured egress proxy.
func dialGuarded(ctx context.Context, network, addr string) (net.Conn, error) {
	control := controlBlockSSRF
	if isEgressProxyAddress(addr) {
		control = controlBlockAlways
	}
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: control}
	return d.DialContext(ctx, network, addr)
}

// RefuseRedirect is an http.Client.CheckRedirect that refuses every
// redirect, so credentials attached to a request never follow a Location
// header to another host.
func RefuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("netguard: refusing redirect to %s: exporter endpoints must not redirect (credential-exfiltration guard): %w", req.URL.Redacted(), ErrBlocked)
}

var (
	proxyFromEnvironment = EgressProxy
	lookupIPAddr         = net.DefaultResolver.LookupIPAddr
)

// EgressProxy picks the proxy for an exporter, report-sink or alert request:
// the PODTRACE_EGRESS_* proxy when one is configured, otherwise the standard
// HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment. It applies no address guard of
// its own; HardenedTransport wraps it in one.
func EgressProxy(req *http.Request) (*url.URL, error) {
	p := config.EgressProxySettings()
	if !p.Set() {
		return http.ProxyFromEnvironment(req)
	}
	cfg := httpproxy.Config{HTTPProxy: p.HTTPProxy, HTTPSProxy: p.HTTPSProxy, NoProxy: p.NoProxy}
	return cfg.ProxyFunc()(req.URL)
}

// guardedProxy keeps HTTP(S)_PROXY support without letting it bypass the
// dial guard. Behind a proxy the dialer only ever sees the proxy's
// address, so the target host is checked here instead: a literal IP
// directly, a name by resolving it locally and refusing if any address is
// blocked.
//
// A direct request whose target is the proxy's own address is checked the
// same way: the dialer relaxes the private-range check for that address so
// the proxy hop works, and must not relax it for a tenant endpoint that
// merely names it.
func guardedProxy(req *http.Request) (*url.URL, error) {
	proxyURL, err := proxyFromEnvironment(req)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		if isEgressProxyAddress(proxyDialAddress(req.URL.Scheme + "://" + req.URL.Host)) {
			if err := checkTarget(req.Context(), req.URL.Hostname(), "exporter request to the proxy address"); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	if err := checkTarget(req.Context(), req.URL.Hostname(), "proxied exporter request"); err != nil {
		return nil, err
	}
	return proxyURL, nil
}

func checkTarget(ctx context.Context, host, what string) error {
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("netguard: refusing %s to blocked address %q: %w", what, host, ErrBlocked)
		}
		return nil
	}
	addrs, err := lookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if IsBlockedIP(a.IP) {
			return fmt.Errorf("netguard: refusing %s to %q: resolves to blocked address %s: %w", what, host, a.IP, ErrBlocked)
		}
	}
	return nil
}

// HardenedTransport returns a clone of http.DefaultTransport whose dialer
// refuses blocked addresses and whose proxy hook applies the same check to
// the target of a proxied request.
func HardenedTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = guardedProxy
	tr.DialContext = dialGuarded
	return tr
}

// HardenedClient returns an *http.Client for exporter egress that refuses
// connections to blocked addresses (SSRF guard) and refuses redirects.
func HardenedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     HardenedTransport(),
		CheckRedirect: RefuseRedirect,
	}
}
