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
	"syscall"
	"time"

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

// RefuseRedirect is an http.Client.CheckRedirect that refuses every
// redirect, so credentials attached to a request never follow a Location
// header to another host.
func RefuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("netguard: refusing redirect to %s: exporter endpoints must not redirect (credential-exfiltration guard): %w", req.URL.Redacted(), ErrBlocked)
}

var (
	proxyFromEnvironment = http.ProxyFromEnvironment
	lookupIPAddr         = net.DefaultResolver.LookupIPAddr
)

// guardedProxy keeps HTTP(S)_PROXY support without letting it bypass the
// dial guard. Behind a proxy the dialer only ever sees the proxy's
// address, so the target host is checked here instead: a literal IP
// directly, a name by resolving it locally and refusing if any address is
// blocked.
func guardedProxy(req *http.Request) (*url.URL, error) {
	proxyURL, err := proxyFromEnvironment(req)
	if err != nil || proxyURL == nil {
		return proxyURL, err
	}
	if err := checkProxiedTarget(req.Context(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	return proxyURL, nil
}

func checkProxiedTarget(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("netguard: refusing proxied exporter request to blocked address %q: %w", host, ErrBlocked)
		}
		return nil
	}
	addrs, err := lookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if IsBlockedIP(a.IP) {
			return fmt.Errorf("netguard: refusing proxied exporter request to %q: resolves to blocked address %s: %w", host, a.IP, ErrBlocked)
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
	tr.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   controlBlockSSRF,
	}).DialContext
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
