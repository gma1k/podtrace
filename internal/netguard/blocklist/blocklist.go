// Package blocklist is the one definition of the addresses an exporter must
// never reach. It has no dependencies so the API admission checks and the
// runtime egress guard (internal/netguard) judge an endpoint identically.
package blocklist

import (
	"net"
	"strings"
)

var metadataHosts = []net.IP{
	net.ParseIP("fd00:ec2::254"),   // AWS IMDS over IPv6
	net.ParseIP("100.100.100.200"), // Alibaba Cloud metadata
	net.ParseIP("168.63.129.16"),   // Azure WireServer / host agent
}

var nat64Prefix = [12]byte{0x00, 0x64, 0xff, 0x9b}

// IsBlocked reports whether ip is cloud-metadata / link-local
// (169.254.0.0/16, fe80::/10), a known metadata host outside that range, the
// unspecified address, or multicast. An IPv4 address embedded in a NAT64 or
// IPv4-compatible IPv6 address is judged as the IPv4 address it reaches;
// IPv4-mapped forms are covered by net.IP itself. A nil ip is blocked.
func IsBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := EmbeddedIPv4(ip); v4 != nil {
		return IsBlocked(v4)
	}
	if ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, m := range metadataHosts {
		if ip.Equal(m) {
			return true
		}
	}
	return false
}

// EmbeddedIPv4 returns the IPv4 address carried in the low 32 bits of a
// NAT64 (64:ff9b::/96) or IPv4-compatible (::/96, excluding :: and ::1)
// IPv6 address, or nil.
func EmbeddedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil
	}
	switch [12]byte(ip16[:12]) {
	case nat64Prefix:
	case [12]byte{}:
		if ip16[12] == 0 && ip16[13] == 0 && ip16[14] == 0 && ip16[15] <= 1 {
			return nil
		}
	default:
		return nil
	}
	return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
}

// IsBlockedHost judges an endpoint host as the dial guard will: a literal
// IP by IsBlocked, a zone-scoped literal (fe80::1%eth0) as blocked because
// the dialer refuses it, and a DNS name as allowed here (the dial guard
// checks the address it resolves to).
func IsBlockedHost(host string) bool {
	if strings.Contains(host, "%") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return IsBlocked(ip)
}
