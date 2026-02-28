package events

import (
	"fmt"
	"strings"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

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
	EventUnlink // 29
	EventRename // 30
)

type Event struct {
	Timestamp    uint64
	PID          uint32
	CgroupID     uint64
	NetNsID      uint32 // V4: network namespace inum (0 if kernel BTF unavailable)
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
}

func (e *Event) Latency() time.Duration {
	return time.Duration(e.LatencyNS) * time.Nanosecond
}

func (e *Event) TimestampTime() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

func (e *Event) TypeString() string {
	switch e.Type {
	case EventDNS:
		return "DNS"
	case EventConnect:
		return "NET"
	case EventTCPSend, EventTCPRecv, EventTCPState, EventUDPSend, EventUDPRecv:
		return "NET"
	case EventWrite, EventRead:
		return "FS"
	case EventFsync:
		return "FS"
	case EventSchedSwitch:
		return "CPU"
	case EventPageFault, EventOOMKill:
		return "MEM"
	case EventHTTPReq, EventHTTPResp:
		return "HTTP"
	case EventLockContention:
		return "LOCK"
	case EventTCPRetrans, EventNetDevError:
		return "NET"
	case EventDBQuery:
		return "DB"
	case EventExec, EventFork, EventOpen, EventClose:
		return "PROC"
	case EventTLSHandshake, EventTLSError:
		return "TLS"
	case EventResourceLimit:
		return "RESOURCE"
	case EventPoolAcquire, EventPoolRelease, EventPoolExhausted:
		return "POOL"
	case EventUnlink, EventRename:
		return "FS"
	default:
		return "UNKNOWN"
	}
}

// formatEventMessage is the shared implementation for FormatMessage and
// FormatRealtimeMessage. The realtime parameter controls threshold selection
// and a few minor wording differences.
func formatEventMessage(e *Event, realtime bool) string {
	latencyMs := float64(e.LatencyNS) / float64(config.NSPerMS)
	maxTargetLen := config.MaxTargetStringLength

	// Choose the right TCP threshold based on mode.
	tcpThresholdMS := config.TCPLatencySpikeThresholdMS
	if realtime {
		tcpThresholdMS = config.TCPRealtimeThresholdMS
	}

	switch e.Type {
	case EventDNS:
		if e.Error != 0 {
			return fmt.Sprintf("[DNS] lookup %s failed: error %d", sanitizeString(truncateString(e.Target, maxTargetLen)), e.Error)
		}
		return fmt.Sprintf("[DNS] lookup %s took %.2fms", sanitizeString(truncateString(e.Target, maxTargetLen)), latencyMs)

	case EventConnect:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" || target == "?" {
			target = "file"
		}
		if e.Error != 0 {
			return fmt.Sprintf("[NET] connect to %s failed: error %d", sanitizeString(target), e.Error)
		}
		if realtime {
			return fmt.Sprintf("[NET] connect to %s (%.2fms)", sanitizeString(target), latencyMs)
		}
		if latencyMs > config.ConnectLatencyThresholdMS {
			return fmt.Sprintf("[NET] connect to %s took %.2fms", sanitizeString(target), latencyMs)
		}
		return ""

	case EventTCPSend:
		if e.Error < 0 && e.Error != -config.EAGAIN {
			return fmt.Sprintf("[NET] TCP send error: %d", e.Error)
		}
		if latencyMs > tcpThresholdMS {
			label := "latency spike"
			if realtime {
				label = "latency"
			}
			msg := fmt.Sprintf("[NET] TCP send %s: %.2fms", label, latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventTCPRecv:
		if e.Error < 0 && e.Error != -config.EAGAIN {
			return fmt.Sprintf("[NET] TCP recv error: %d", e.Error)
		}
		if latencyMs > tcpThresholdMS {
			label := "RTT spike"
			if realtime {
				label = "RTT"
			}
			msg := fmt.Sprintf("[NET] TCP recv %s: %.2fms", label, latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventUDPSend:
		if e.Error < 0 {
			return fmt.Sprintf("[NET] UDP send error: %d", e.Error)
		}
		if latencyMs > config.UDPLatencySpikeThresholdMS {
			msg := fmt.Sprintf("[NET] UDP send latency spike: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventUDPRecv:
		if e.Error < 0 {
			return fmt.Sprintf("[NET] UDP recv error: %d", e.Error)
		}
		if latencyMs > config.UDPLatencySpikeThresholdMS {
			msg := fmt.Sprintf("[NET] UDP recv latency spike: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventHTTPReq:
		// HTTP events are not surfaced in realtime mode (original behavior).
		if realtime {
			break
		}
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "unknown"
		}
		return fmt.Sprintf("[HTTP] request to %s took %.2fms", sanitizeString(target), latencyMs)

	case EventHTTPResp:
		// HTTP events are not surfaced in realtime mode (original behavior).
		if realtime {
			break
		}
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "unknown"
		}
		msg := fmt.Sprintf("[HTTP] response from %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventTCPState:
		stateStr := TCPStateString(e.TCPState)
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "unknown"
		}
		if realtime {
			return fmt.Sprintf("[NET] TCP state: %s for %s", stateStr, sanitizeString(target))
		}
		return fmt.Sprintf("[NET] TCP state change to %s for %s", stateStr, sanitizeString(target))

	case EventPageFault:
		return fmt.Sprintf("[MEM] Page fault (error: %d)", e.Error)

	case EventOOMKill:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "unknown"
		}
		memMB := float64(e.Bytes) / float64(config.MB)
		return fmt.Sprintf("[MEM] OOM kill: %s (%.2f MB)", sanitizeString(target), memMB)

	case EventWrite:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" || target == "?" {
			target = "file"
		}
		msg := fmt.Sprintf("[FS] write() to %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventRead:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" || target == "?" {
			target = "file"
		}
		msg := fmt.Sprintf("[FS] read() from %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventFsync:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "file"
		}
		return fmt.Sprintf("[FS] fsync() to %s took %.2fms", sanitizeString(target), latencyMs)

	case EventSchedSwitch:
		return fmt.Sprintf("[CPU] thread blocked %.2fms", latencyMs)

	case EventLockContention:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "lock"
		}
		return fmt.Sprintf("[LOCK] contention on %s (%.2fms)", sanitizeString(target), latencyMs)

	case EventTCPRetrans:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "unknown"
		}
		if realtime {
			return fmt.Sprintf("[NET] TCP retransmission for %s", sanitizeString(target))
		}
		return fmt.Sprintf("[NET] TCP retransmission detected for %s", sanitizeString(target))

	case EventNetDevError:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "iface"
		}
		return fmt.Sprintf("[NET] network device errors on %s (error=%d)", sanitizeString(target), e.Error)

	case EventDBQuery:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "query"
		}
		return fmt.Sprintf("[DB] query pattern %s took %.2fms", sanitizeString(target), latencyMs)

	case EventExec:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "unknown"
		}
		if e.Error != 0 {
			return fmt.Sprintf("[PROC] execve %s failed: error %d", sanitizeString(target), e.Error)
		}
		return fmt.Sprintf("[PROC] execve %s took %.2fms", sanitizeString(target), latencyMs)

	case EventFork:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "child"
		}
		return fmt.Sprintf("[PROC] fork created pid %d (%s)", e.PID, sanitizeString(target))

	case EventOpen:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "file"
		}
		fd := int64(e.Bytes)
		if e.Error != 0 {
			return fmt.Sprintf("[FS] open() %s failed: error %d", sanitizeString(target), e.Error)
		}
		if fd >= 0 {
			if realtime {
				return fmt.Sprintf("[FS] open() %s fd=%d (%.2fms)", sanitizeString(target), fd, latencyMs)
			}
			return fmt.Sprintf("[FS] open() %s fd=%d took %.2fms", sanitizeString(target), fd, latencyMs)
		}
		if realtime {
			return fmt.Sprintf("[FS] open() %s (%.2fms)", sanitizeString(target), latencyMs)
		}
		return fmt.Sprintf("[FS] open() %s took %.2fms", sanitizeString(target), latencyMs)

	case EventClose:
		fd := int64(e.Bytes)
		if fd >= 0 {
			return fmt.Sprintf("[FS] close() fd=%d", fd)
		}
		return "[FS] close()"

	case EventTLSHandshake:
		if e.Error != 0 {
			return fmt.Sprintf("[TLS] handshake failed: error %d (%.2fms)", e.Error, latencyMs)
		}
		return fmt.Sprintf("[TLS] handshake completed (%.2fms)", latencyMs)

	case EventTLSError:
		return fmt.Sprintf("[TLS] error: %d", e.Error)

	case EventResourceLimit:
		utilization := uint32(e.Error)
		resourceType := e.TCPState

		var resourceName string
		switch resourceType {
		case 0:
			resourceName = "CPU"
		case 1:
			resourceName = "Memory"
		case 2:
			resourceName = "I/O"
		default:
			resourceName = "Resource"
		}

		var severity string
		emergPct := uint32(config.AlertEmergPct)
		critPct := uint32(config.AlertCritPct)
		warnPct := uint32(config.AlertWarnPct)
		if utilization >= emergPct {
			severity = "EMERGENCY"
		} else if utilization >= critPct {
			severity = "CRITICAL"
		} else if utilization >= warnPct {
			severity = "WARNING"
		} else {
			return ""
		}

		return fmt.Sprintf("[RESOURCE] %s %s utilization: %d%%", severity, resourceName, utilization)

	case EventPoolAcquire:
		poolID := truncateString(e.Target, maxTargetLen)
		if poolID == "" {
			poolID = "default"
		}
		if realtime {
			return fmt.Sprintf("[POOL] acquire from %s (%.2fms)", sanitizeString(poolID), latencyMs)
		}
		return fmt.Sprintf("[POOL] acquire connection from %s (%.2fms)", sanitizeString(poolID), latencyMs)

	case EventPoolRelease:
		poolID := truncateString(e.Target, maxTargetLen)
		if poolID == "" {
			poolID = "default"
		}
		if realtime {
			return fmt.Sprintf("[POOL] release to %s", sanitizeString(poolID))
		}
		return fmt.Sprintf("[POOL] release connection to %s", sanitizeString(poolID))

	case EventPoolExhausted:
		poolID := truncateString(e.Target, maxTargetLen)
		if poolID == "" {
			poolID = "default"
		}
		if realtime {
			return fmt.Sprintf("[POOL] %s exhausted (%.2fms wait)", sanitizeString(poolID), latencyMs)
		}
		return fmt.Sprintf("[POOL] pool %s exhausted, wait %.2fms", sanitizeString(poolID), latencyMs)

	case EventUnlink:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "file"
		}
		if e.Error != 0 {
			return fmt.Sprintf("[FS] unlink() %s failed: error %d", sanitizeString(target), e.Error)
		}
		return fmt.Sprintf("[FS] unlink() %s took %.2fms", sanitizeString(target), latencyMs)

	case EventRename:
		target := truncateString(e.Target, maxTargetLen)
		if target == "" {
			target = "file"
		}
		if e.Error != 0 {
			return fmt.Sprintf("[FS] rename() %s failed: error %d", sanitizeString(target), e.Error)
		}
		return fmt.Sprintf("[FS] rename() %s took %.2fms", sanitizeString(target), latencyMs)

	default:
		return fmt.Sprintf("[UNKNOWN] event type %d", e.Type)
	}
	// Reached when a case uses break (e.g. HTTP events in realtime mode).
	return fmt.Sprintf("[UNKNOWN] event type %d", e.Type)
}

func (e *Event) FormatMessage() string {
	return formatEventMessage(e, false)
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

func (e *Event) FormatRealtimeMessage() string {
	return formatEventMessage(e, true)
}
