package events

import "slices"

// Filter categories are the user-facing names accepted by --filter and by
// spec.filters on PodTrace and PodTraceSession.
const (
	FilterCategoryDNS    = "dns"
	FilterCategoryNet    = "net"
	FilterCategoryFS     = "fs"
	FilterCategoryCPU    = "cpu"
	FilterCategoryProc   = "proc"
	FilterCategoryCrypto = "crypto"
	FilterCategoryUSDT   = "usdt"
)

// filterCategoryAlways marks event types that are delivered whatever filter
// is set: they carry no activity of their own but close out a request the
// filtered events belong to.
const filterCategoryAlways = "*"

// filterCategoryOf is the single mapping from event type to filter category,
// shared by the CLI/session filter and the agent router so the same filter
// list selects the same events everywhere.
var filterCategoryOf = map[EventType]string{
	EventDNS:      FilterCategoryDNS,
	EventDNSQuery: FilterCategoryDNS,

	EventConnect:       FilterCategoryNet,
	EventConnectResult: FilterCategoryNet,
	EventTCPSend:       FilterCategoryNet,
	EventTCPRecv:       FilterCategoryNet,
	EventUDPSend:       FilterCategoryNet,
	EventUDPRecv:       FilterCategoryNet,
	EventTCPState:      FilterCategoryNet,
	EventTCPRetrans:    FilterCategoryNet,
	EventTCPRTT:        FilterCategoryNet,
	EventNetDevError:   FilterCategoryNet,
	EventTLSHandshake:  FilterCategoryNet,
	EventTLSError:      FilterCategoryNet,
	EventHTTPReq:       FilterCategoryNet,
	EventHTTPResp:      FilterCategoryNet,
	EventHTTP3:         FilterCategoryNet,
	EventGRPCMethod:    FilterCategoryNet,
	EventFastCGIReq:    FilterCategoryNet,
	EventFastCGIResp:   FilterCategoryNet,
	EventDBQuery:       FilterCategoryNet,
	EventRedisCmd:      FilterCategoryNet,
	EventMemcachedCmd:  FilterCategoryNet,
	EventKafkaProduce:  FilterCategoryNet,
	EventKafkaFetch:    FilterCategoryNet,
	EventPoolAcquire:   FilterCategoryNet,
	EventPoolRelease:   FilterCategoryNet,
	EventPoolExhausted: FilterCategoryNet,
	EventDBAcquire:     FilterCategoryNet,
	EventDBPoolStats:   FilterCategoryNet,

	EventOpen:   FilterCategoryFS,
	EventClose:  FilterCategoryFS,
	EventRead:   FilterCategoryFS,
	EventWrite:  FilterCategoryFS,
	EventFsync:  FilterCategoryFS,
	EventUnlink: FilterCategoryFS,
	EventRename: FilterCategoryFS,

	EventSchedSwitch:    FilterCategoryCPU,
	EventLockContention: FilterCategoryCPU,

	EventExec:          FilterCategoryProc,
	EventFork:          FilterCategoryProc,
	EventOOMKill:       FilterCategoryProc,
	EventPageFault:     FilterCategoryProc,
	EventResourceLimit: FilterCategoryProc,

	EventAFALG: FilterCategoryCrypto,

	EventUSDT: FilterCategoryUSDT,

	EventRequestDone: filterCategoryAlways,
}

// FilterCategories returns every filter category name in stable order.
func FilterCategories() []string {
	return []string{
		FilterCategoryDNS,
		FilterCategoryNet,
		FilterCategoryFS,
		FilterCategoryCPU,
		FilterCategoryProc,
		FilterCategoryCrypto,
		FilterCategoryUSDT,
	}
}

// IsFilterCategory reports whether name is a known filter category.
func IsFilterCategory(name string) bool {
	for _, c := range FilterCategories() {
		if c == name {
			return true
		}
	}
	return false
}

// FilterCategoryOf returns the filter category an event type belongs to. It
// returns "" for event types delivered regardless of filter and for unknown
// types.
func FilterCategoryOf(t EventType) string {
	c := filterCategoryOf[t]
	if c == filterCategoryAlways {
		return ""
	}
	return c
}

// DeliveredUnderAnyFilter reports whether an event type passes every
// non-empty filter.
func DeliveredUnderAnyFilter(t EventType) bool {
	return filterCategoryOf[t] == filterCategoryAlways
}

// EventTypesInFilterCategory returns the event types a filter category
// selects, in ascending order. An unknown category selects nothing.
func EventTypesInFilterCategory(category string) []EventType {
	if !IsFilterCategory(category) {
		return nil
	}
	var out []EventType
	for t, c := range filterCategoryOf {
		if c == category {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

// EventTypesDeliveredUnderAnyFilter returns the event types that pass every
// non-empty filter, in ascending order.
func EventTypesDeliveredUnderAnyFilter() []EventType {
	var out []EventType
	for t, c := range filterCategoryOf {
		if c == filterCategoryAlways {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

// MatchesFilter reports whether an event type passes a filter given as a set
// of category names. An empty set matches everything.
func MatchesFilter(t EventType, categories map[string]bool) bool {
	if len(categories) == 0 {
		return true
	}
	c := filterCategoryOf[t]
	if c == filterCategoryAlways {
		return true
	}
	return c != "" && categories[c]
}
