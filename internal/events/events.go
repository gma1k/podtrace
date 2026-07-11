package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/podtrace/podtrace/internal/clock"
	"github.com/podtrace/podtrace/internal/safeconv"
)

// PeerIP formats a fused L7<->L4 peer address. v4 is host byte order; family is
// the AF_* value (2=AF_INET, 10=AF_INET6). Returns "" if unknown/unspecified.
func PeerIP(family uint8, v4 uint32, v6 [16]byte) string {
	switch family {
	case 2:
		if v4 == 0 {
			return ""
		}
		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, v4)
		return ip.String()
	case 10:
		ip := net.IP(v6[:])
		if ip.IsUnspecified() {
			return ""
		}
		return ip.String()
	default:
		return ""
	}
}

func sanitizeString(s string) string {
	return strings.ReplaceAll(s, "%", "%%")
}

func truncateString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

type EventType uint32

const (
	EventDNS EventType = iota
	EventConnect
	EventTCPSend
	EventTCPRecv
	EventWrite
	EventRead
	EventFsync
	EventSchedSwitch
	EventTCPState
	EventPageFault
	EventOOMKill
	EventUDPSend
	EventUDPRecv
	EventHTTPReq
	EventHTTPResp
	EventLockContention
	EventTCPRetrans
	EventNetDevError
	EventDBQuery
	EventExec
	EventFork
	EventOpen
	EventClose
	EventTLSHandshake
	EventTLSError
	EventResourceLimit
	EventPoolAcquire
	EventPoolRelease
	EventPoolExhausted
	EventUnlink
	EventRename
	EventRedisCmd
	EventMemcachedCmd
	EventFastCGIReq
	EventFastCGIResp
	EventGRPCMethod
	EventKafkaProduce
	EventKafkaFetch
	EventDNSQuery
	EventAFALG
	EventHTTP3
)

type Event struct {
	Timestamp    uint64
	PID          uint32
	CgroupID     uint64
	NetNsID      uint32   // V4: network namespace inum (0 if kernel BTF unavailable)
	DNSServerIP  uint32   // V5: upstream resolver IPv4 for DNS events (0 otherwise)
	DNSTransport uint8    // V5: 0=UDP, 1=TCP for DNS events
	DNSServerIP6 [16]byte // V6: upstream resolver IPv6 for DNS events
	PeerSrcIP    string   // V7: L7<->L4 fused local address ("" if unknown)
	PeerDstIP    string   // V7: L7<->L4 fused remote/peer address
	PeerSrcPort  uint16   // V7: local port
	PeerDstPort  uint16   // V7: remote/peer port
	ProcessName  string
	Type         EventType
	LatencyNS    uint64
	Error        int32
	Bytes        uint64
	TCPState     uint32
	StackKey     uint64
	Stack        []uint64
	Target       string
	Details      string
	TraceID      string
	SpanID       string
	ParentSpanID string
	TraceFlags   uint8
	TraceState   string

	CorrelationID uint64

	K8s *K8sMetadata
}

func (e *Event) Latency() time.Duration {
	return time.Duration(safeconv.Uint64ToInt64(e.LatencyNS)) * time.Nanosecond
}

// IsError reports whether the event represents a failure.
func (e *Event) IsError() bool {
	switch e.Type {
	case EventResourceLimit:
		return false
	default:
		return e.Error != 0
	}
}

// TimestampTime returns the event's timestamp as wall-clock time.
func (e *Event) TimestampTime() time.Time {
	return clock.BPFTimestampToWall(e.Timestamp)
}

// HTTP transport for EventHTTPReq/EventHTTPResp, carried in TCPState (unused
// for HTTP events otherwise). Encoded as a bitfield: bit 0 = TLS (encrypted),
// bit 1 = HTTP/2.
const (
	HTTPTransportPlaintext uint32 = 0 // HTTP/1.x cleartext sockets
	HTTPTransportTLS       uint32 = 1 // HTTP/1.x over TLS (OpenSSL/GnuTLS/Go)
	HTTPTransportH2C       uint32 = 2 // HTTP/2 cleartext
	HTTPTransportH2TLS     uint32 = 3 // HTTP/2 over TLS (Go crypto/tls)
	HTTPTransportH3        uint32 = 5 // HTTP/3 over QUIC: H3 bit | TLS bit

	httpTransportTLSBit uint32 = 1
	httpTransportH2Bit  uint32 = 2
	httpTransportH3Bit  uint32 = 4
)

// HTTPScheme returns the URL scheme implied by an HTTP event's transport:
// "https" for any TLS-captured traffic, "http" for cleartext (HTTP/1.x or h2c).
func (e *Event) HTTPScheme() string {
	if e.TCPState&httpTransportTLSBit != 0 {
		return "https"
	}
	return "http"
}

// HTTPProtoLabel is the protocol label for an HTTP event, reflecting its
// transport: "HTTP/3" for QUIC, "HTTP/2" for any h2 traffic, else "HTTPS" over
// TLS or "HTTP".
func (e *Event) HTTPProtoLabel() string {
	if e.TCPState&httpTransportH3Bit != 0 {
		return "HTTP/3"
	}
	if e.TCPState&httpTransportH2Bit != 0 {
		return "HTTP/2"
	}
	if e.TCPState&httpTransportTLSBit != 0 {
		return "HTTPS"
	}
	return "HTTP"
}

func (e *Event) TypeString() string {
	switch e.Type {
	case EventDNS, EventDNSQuery:
		return "DNS"
	case EventConnect:
		return "NET"
	case EventTCPSend, EventTCPRecv, EventTCPState, EventUDPSend, EventUDPRecv:
		return "NET"
	case EventWrite, EventRead:
		return "FS"
	case EventFsync:
		return "FS"
	case EventOpen, EventClose:
		return "FS"
	case EventSchedSwitch:
		return "CPU"
	case EventPageFault, EventOOMKill:
		return "MEM"
	case EventHTTPReq, EventHTTPResp:
		return e.HTTPProtoLabel()
	case EventLockContention:
		return "LOCK"
	case EventTCPRetrans, EventNetDevError:
		return "NET"
	case EventDBQuery:
		return "DB"
	case EventExec, EventFork:
		return "PROC"
	case EventTLSHandshake, EventTLSError:
		return "TLS"
	case EventResourceLimit:
		return "RESOURCE"
	case EventPoolAcquire, EventPoolRelease, EventPoolExhausted:
		return "POOL"
	case EventUnlink, EventRename:
		return "FS"
	case EventRedisCmd, EventMemcachedCmd:
		return "CACHE"
	case EventFastCGIReq, EventFastCGIResp:
		return "FASTCGI"
	case EventGRPCMethod:
		return "gRPC"
	case EventKafkaProduce, EventKafkaFetch:
		return "KAFKA"
	case EventAFALG:
		return "CRYPTO"
	case EventHTTP3:
		return "HTTP/3"
	default:
		return "UNKNOWN"
	}
}

// dnsQTypeName maps a DNS query type to its mnemonic (carried in TCPState for
// EVENT_DNS).
func dnsQTypeName(t uint32) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 33:
		return "SRV"
	case 12:
		return "PTR"
	case 16:
		return "TXT"
	case 15:
		return "MX"
	case 2:
		return "NS"
	case 6:
		return "SOA"
	case 0:
		return "lookup"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// dnsServerString formats the upstream resolver IPv4.
func dnsServerString(v uint32) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
}

// DNSServerAddr returns the upstream resolver address for a DNS event,
// preferring the IPv6 server when present, else the IPv4 one.
func (e *Event) DNSServerAddr() string {
	return dnsServerStr(e)
}

// dnsServerStr returns the upstream resolver address for a DNS event, preferring
// the IPv6 server when present, else the IPv4 one. Returns "" when unknown.
func dnsServerStr(e *Event) string {
	for _, b := range e.DNSServerIP6 {
		if b != 0 {
			const hex = "0123456789abcdef"
			out := make([]byte, 0, 39)
			for i := 0; i < 16; i += 2 {
				if i > 0 {
					out = append(out, ':')
				}
				out = append(out, hex[e.DNSServerIP6[i]>>4], hex[e.DNSServerIP6[i]&0xf],
					hex[e.DNSServerIP6[i+1]>>4], hex[e.DNSServerIP6[i+1]&0xf])
			}
			return string(out)
		}
	}
	return dnsServerString(e.DNSServerIP)
}

// dnsRCodeName maps a DNS response code (carried in Error for EVENT_DNS) to its
// mnemonic.
func dnsRCodeName(rcode int32) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("rcode %d", rcode)
	}
}

// IsCopyFailSignal reports whether this event is an AF_ALG bind of an "aead"
// transform by an unprivileged (uid != 0) caller.
func (e *Event) IsCopyFailSignal() bool {
	return e.Type == EventAFALG && e.Target == "aead" && e.Bytes != 0
}

func TCPStateString(state uint32) string {
	states := map[uint32]string{
		1:  "ESTABLISHED",
		2:  "SYN_SENT",
		3:  "SYN_RECV",
		4:  "FIN_WAIT1",
		5:  "FIN_WAIT2",
		6:  "TIME_WAIT",
		7:  "CLOSE",
		8:  "CLOSE_WAIT",
		9:  "LAST_ACK",
		10: "LISTEN",
		11: "CLOSING",
		12: "NEW_SYN_RECV",
	}
	if name, ok := states[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}
