package parser

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// canonicalIPv6Target rewrites the kernel's IPv6 "address:port" form, eight
// hex groups and a port joined by colons with no brackets, into the
// bracketed, compressed form net.JoinHostPort writes ("[::1]:8086"), so the
// port can be told apart from the address.
func canonicalIPv6Target(target string) string {
	if strings.Count(target, ":") != 8 {
		return target
	}
	cut := strings.LastIndexByte(target, ':')
	addr, port := target[:cut], target[cut+1:]
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || strconv.FormatUint(p, 10) != port {
		return target
	}
	ip := make(net.IP, net.IPv6len)
	for i, group := range strings.Split(addr, ":") {
		if group == "" || len(group) > 4 {
			return target
		}
		padded := strings.Repeat("0", 4-len(group)) + group
		if _, err := hex.Decode(ip[2*i:2*i+2], []byte(padded)); err != nil {
			return target
		}
	}
	return net.JoinHostPort(ip.String(), port)
}
