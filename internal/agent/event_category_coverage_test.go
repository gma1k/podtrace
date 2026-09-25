package agent

import (
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/events"
)

var networkEventTypes = []events.EventType{
	events.EventConnect,
	events.EventTCPSend,
	events.EventTCPRecv,
	events.EventUDPSend,
	events.EventUDPRecv,
	events.EventTCPState,
	events.EventTCPRetrans,
	events.EventNetDevError,
	events.EventTCPRTT,
	events.EventConnectResult,
}

func TestTheNetCategoryClaimsEveryNetworkEventType(t *testing.T) {
	claimed := map[events.EventType]bool{}
	for _, et := range filterToEventTypes(podtracev1alpha1.FilterNet) {
		claimed[et] = true
	}

	for _, et := range networkEventTypes {
		if !claimed[et] {
			e := &events.Event{Type: et}
			t.Errorf("%s (type %d) is emitted by the network probes but the net category "+
				"does not claim it, so a PodTrace with filters: [net] drops it", e.TypeString(), et)
		}
	}
}

func TestNoCategoryClaimsAnEventTypeTwice(t *testing.T) {
	categories := []podtracev1alpha1.EventFilter{
		podtracev1alpha1.FilterDNS,
		podtracev1alpha1.FilterNet,
		podtracev1alpha1.FilterFS,
		podtracev1alpha1.FilterCPU,
		podtracev1alpha1.FilterProc,
		podtracev1alpha1.FilterCrypto,
		podtracev1alpha1.FilterUSDT,
	}

	owner := map[events.EventType]podtracev1alpha1.EventFilter{}
	for _, f := range categories {
		for _, et := range filterToEventTypes(f) {
			if prev, dup := owner[et]; dup {
				e := &events.Event{Type: et}
				t.Errorf("%s is claimed by both %q and %q; enabling either category would "+
					"attach overlapping probe sets", e.TypeString(), prev, f)
			}
			owner[et] = f
		}
	}
}
