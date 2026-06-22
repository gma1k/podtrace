package agent

import (
	"fmt"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/events"
)

// emitCopyFailAlert raises a warning when an AF_ALG "aead" socket is bound by
// an unprivileged process, the interface precondition for CVE-2026-31431
// ("Copy-Fail").
func emitCopyFailAlert(ev *events.Event) {
	if ev == nil || !ev.IsCopyFailSignal() {
		return
	}
	mgr := alerting.GetGlobalManager()
	if mgr == nil {
		return
	}

	var podName, namespace string
	if ev.K8s != nil {
		podName = ev.K8s.PodName
		namespace = ev.K8s.Namespace
	}

	mgr.SendAlert(&alerting.Alert{
		Severity:  alerting.SeverityWarning,
		Title:     "Possible privilege-escalation attempt: Copy-Fail (CVE-2026-31431)",
		Message:   fmt.Sprintf("A non-root process could gain root on unpatched nodes. Process %q (pid %d, uid %d) bound an AF_ALG aead transform %q.", ev.ProcessName, ev.PID, ev.Bytes, ev.Details),
		Timestamp: ev.TimestampTime(),
		Source:    "crypto-detector",
		PodName:   podName,
		Namespace: namespace,
		Context: map[string]interface{}{
			"salg_type": ev.Target,
			"salg_name": ev.Details,
			"uid":       ev.Bytes,
			"cve":       "CVE-2026-31431",
		},
		Recommendations: []string{
			"Confirm whether AF_ALG/aead use is expected for this workload",
			"Patch the node kernel (mainline commit a664bf3d603d)",
			"If unused, blacklist the algif_aead kernel module",
		},
	})
}
