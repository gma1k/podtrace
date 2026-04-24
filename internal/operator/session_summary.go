package operator

import (
	"context"
	"encoding/json"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// sessionSummaryJSON mirrors the SessionSummary shape the CLI writes to
// /dev/termination-log. Kept as a dedicated operator-side struct so the
// controller does not take a compile-time dependency on cmd/podtrace.
type sessionSummaryJSON struct {
	TotalEvents    int64  `json:"totalEvents"`
	DNSEvents      int64  `json:"dnsEvents,omitempty"`
	NetEvents      int64  `json:"netEvents,omitempty"`
	FSEvents       int64  `json:"fsEvents,omitempty"`
	CPUEvents      int64  `json:"cpuEvents,omitempty"`
	ProcEvents     int64  `json:"procEvents,omitempty"`
	ErrorsDetected int32  `json:"errorsDetected,omitempty"`
	DurationMS     int64  `json:"durationMs,omitempty"`
	Node           string `json:"node,omitempty"`
}

// populateSessionSummaries walks the session's child Jobs, reads the
// matching Pod's terminationMessage, and rolls the per-Job counts up
// into the session's status.Summary plus per-Job status.jobs[i].eventCount.
//
// Missing termination messages are non-fatal: Jobs that have not yet
// completed, or that crashed before writing, just contribute zero to
// the rollup. This keeps a partially-failing session observable
// instead of silently stuck.
func populateSessionSummaries(ctx context.Context, c client.Client, session *podtracev1alpha1.PodTraceSession, jobs []batchv1.Job) error {
	if session == nil {
		return nil
	}
	summaryByNode := map[string]sessionSummaryJSON{}
	for i := range jobs {
		j := &jobs[i]
		summary, err := readTerminationSummaryForJob(ctx, c, j)
		if err != nil {
			// Log-in-context by returning: reconciler treats the
			// whole call as transient and re-queues. A missing pod
			// (GC'd after TTL) returns zero-value, not error.
			return err
		}
		if summary == nil {
			continue
		}
		node := j.Labels[LabelNodeName]
		if node == "" {
			node = summary.Node
		}
		summaryByNode[node] = *summary
	}

	// Fold per-Job EventCount back into the SessionJobRef array. The
	// array has already been built by makeSessionJobRefs in the main
	// reconcile path; we only mutate the EventCount field here so we
	// do not race with phase/time fields.
	for i := range session.Status.Jobs {
		ref := &session.Status.Jobs[i]
		if s, ok := summaryByNode[ref.Node]; ok {
			ref.EventCount = s.TotalEvents
		}
	}

	session.Status.Summary = aggregateSessionSummary(summaryByNode)
	return nil
}

// readTerminationSummaryForJob locates the Pod created by a session
// Job, reads its terminationMessage, and decodes the JSON into
// sessionSummaryJSON. Returns (nil, nil) when the pod or termination
// message is missing or malformed — the caller treats that as "no
// data yet," not an error.
func readTerminationSummaryForJob(ctx context.Context, c client.Client, job *batchv1.Job) (*sessionSummaryJSON, error) {
	if job.Status.CompletionTime == nil && job.Status.Failed == 0 {
		// Job has not finished: no terminated container to read from.
		return nil, nil
	}
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(job.Namespace), client.MatchingLabels{
		"job-name": job.Name,
	}); err != nil {
		return nil, fmt.Errorf("list pods for Job %s: %w", job.Name, err)
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name != "podtrace" {
				continue
			}
			if cs.State.Terminated == nil {
				continue
			}
			raw := cs.State.Terminated.Message
			if raw == "" {
				return nil, nil
			}
			var s sessionSummaryJSON
			if err := json.Unmarshal([]byte(raw), &s); err != nil {
				// Malformed termination messages do not block status
				// reconciliation — the CLI may have crashed mid-write
				// or the container runtime truncated below the 4KB
				// ceiling. Returning nil leaves the Job's EventCount
				// at zero without failing the reconcile.
				return nil, nil
			}
			return &s, nil
		}
	}
	return nil, nil
}

// aggregateSessionSummary reduces per-Job summaries to the cluster-wide
// SessionSummary the CRD exposes on status.summary.
func aggregateSessionSummary(byNode map[string]sessionSummaryJSON) *podtracev1alpha1.SessionSummary {
	if len(byNode) == 0 {
		return nil
	}
	out := &podtracev1alpha1.SessionSummary{}
	for _, s := range byNode {
		out.TotalEvents += s.TotalEvents
		out.DNSEvents += s.DNSEvents
		out.NetEvents += s.NetEvents
		out.FSEvents += s.FSEvents
		out.CPUEvents += s.CPUEvents
		out.ProcEvents += s.ProcEvents
		out.ErrorsDetected += s.ErrorsDetected
	}
	return out
}
