// Package netguard hardens outbound HTTP made on behalf of tenant-supplied
// exporter endpoints.
package netguard

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

// IsBlockedIP reports whether ip is an address an exporter must never connect
// to: cloud-metadata / link-local (169.254.0.0/16, fe80::/10), the unspecified
// address, and multicast.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if config.ExporterBlockPrivateRanges() && ip.IsPrivate() {
		return true
	}
	return false
}

// IsLoopbackHost reports whether host is localhost or a loopback IP literal.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateEndpointHost rejects an endpoint whose host is a literal IP an
// exporter must never reach.
func ValidateEndpointHost(host string) error {
	if ip := net.ParseIP(host); ip != nil && IsBlockedIP(ip) {
		return fmt.Errorf("endpoint host %q is a blocked address (link-local/metadata)", host)
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
		return fmt.Errorf("netguard: refusing exporter connection to blocked address %q", address)
	}
	return nil
}

func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("netguard: refusing redirect to %s: exporter endpoints must not redirect (credential-exfiltration guard)", req.URL.Redacted())
}

// HardenedClient returns an *http.Client for exporter egress that refuses
// connections to blocked addresses (SSRF guard) and refuses redirects.
func HardenedClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   controlBlockSSRF,
	}).DialContext
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: refuseRedirect,
	}
}
