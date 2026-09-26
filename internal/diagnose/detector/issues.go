package detector

import (
	"github.com/gma1k/podtrace/internal/alerting"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

// DetectIssues returns the typed issues present in a batch of events.
func DetectIssues(allEvents []*events.Event, errorRateThreshold, rttSpikeThreshold float64) []Issue {
	var issues []Issue

	var connectEvents []*events.Event
	for _, e := range allEvents {
		if e == nil {
			continue
		}
		if events.CountsAsConnectionAttempt(e.Type, e.Error != 0) && !events.IsUnreachableConnect(e) {
			connectEvents = append(connectEvents, e)
		}
	}

	if len(connectEvents) > 0 {
		errors := 0
		for _, e := range connectEvents {
			if e.Error != 0 {
				errors++
			}
		}
		errorRate := float64(errors) / float64(len(connectEvents)) * 100
		if errorRate > errorRateThreshold {
			issues = append(issues, Issue{
				ID:       IDConnectionFailureRate,
				Severity: alerting.SeverityWarning,
				Evidence: []Evidence{
					evidence("error_rate", errorRate, errorRateThreshold, "%"),
					evidence("failed_connections", float64(errors), 0, "count"),
					evidence("total_connections", float64(len(connectEvents)), 0, "count"),
				},
				Remediation: "Check the destination's readiness and any NetworkPolicy or " +
					"firewall between the two; the service map shows which peer is failing.",
				Message: fmtRate("High connection failure rate: %.1f%% (%d/%d) (threshold: %.1f%%)",
					errorRate, errors, len(connectEvents), errorRateThreshold),
			})
		}
	}

	var tcpEvents []*events.Event
	for _, e := range allEvents {
		if e == nil {
			continue
		}
		if e.Type == events.EventTCPSend || e.Type == events.EventTCPRecv {
			tcpEvents = append(tcpEvents, e)
		}
	}

	if len(tcpEvents) > 0 {
		spikes := 0
		for _, e := range tcpEvents {
			if float64(e.LatencyNS)/float64(config.NSPerMS) > rttSpikeThreshold {
				spikes++
			}
		}
		spikeRate := float64(spikes) / float64(len(tcpEvents)) * 100
		if spikeRate > config.SpikeRateThreshold {
			issues = append(issues, Issue{
				ID:       IDRTTSpikeRate,
				Severity: alerting.SeverityWarning,
				Evidence: []Evidence{
					evidence("spike_rate", spikeRate, config.SpikeRateThreshold, "%"),
					evidence("rtt_threshold", rttSpikeThreshold, rttSpikeThreshold, "ms"),
					evidence("spikes", float64(spikes), 0, "count"),
					evidence("total_operations", float64(len(tcpEvents)), 0, "count"),
				},
				Remediation: "Round trips are slow on the wire rather than in the application; " +
					"check node saturation and the network path to the peer.",
				Message: fmtRate("High TCP RTT spike rate: %.1f%% (%d/%d) (threshold: %.1fms)",
					spikeRate, spikes, len(tcpEvents), rttSpikeThreshold),
			})
		}
	}

	var resourceAlerts = make(map[string]int)
	for _, e := range allEvents {
		if e == nil {
			continue
		}
		if e.Type == events.EventResourceLimit {
			// e.Error is int32 carrying the utilization percentage;
			// negative values are non-physical and skipped.
			if e.Error < 0 {
				continue
			}
			utilization := int(e.Error)
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

			key := resourceName
			if current, ok := resourceAlerts[key]; !ok || utilization > current {
				resourceAlerts[key] = utilization
			}
		}
	}

	for resourceName, maxUtil := range resourceAlerts {
		severity, firing := severityForUtilization(maxUtil,
			config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct)
		if !firing {
			continue
		}
		issues = append(issues, Issue{
			ID:       IDResourceSaturation,
			Severity: severity,
			Subject:  Subject{Resource: resourceName},
			Evidence: []Evidence{
				evidence("utilization", float64(maxUtil), float64(config.AlertWarnPct), "%"),
			},
			Remediation: "Raise the container's limit for this resource, or reduce what the " +
				"workload asks of it; saturation here shows up as latency everywhere else.",
			Message: fmtRate("Resource limit %s: %s - %d%% utilization (threshold: %d%% warning, %d%% critical, %d%% emergency)",
				severityLabel(severity), resourceName, maxUtil,
				config.AlertWarnPct, config.AlertCritPct, config.AlertEmergPct),
		})
	}

	return issues
}
