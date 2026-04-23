package agent

import (
	"context"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// DefaultStatusReportInterval matches the TracerConfig default. Tests
// override to a much shorter interval.
const DefaultStatusReportInterval = 30 * time.Second

// StatusWriter patches PodTrace.status.nodeStatus on a timer. One entry
// per node is maintained, keyed on the node name via the
// `patchMergeKey: "node"` strategic-merge marker declared on the Go
// field. Many agents writing concurrently therefore do not overwrite
// each other's entries.
//
// The writer never reads per-CR state directly — it takes a snapshot
// from the router (for cgroup counts) and the per-CR stats table (for
// events/drops) under the router's own lock. This keeps status writes
// off the event hot path.
type StatusWriter struct {
	Client   client.Client
	NodeName string
	Interval time.Duration
	Router   *Router

	Ready func() bool
}

// Run blocks until ctx is done, emitting status patches every
// Interval. Safe to call at most once per StatusWriter instance.
func (w *StatusWriter) Run(ctx context.Context) error {
	interval := w.Interval
	if interval <= 0 {
		interval = DefaultStatusReportInterval
	}
	logger := log.FromContext(ctx).WithName("status-writer")

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := w.emitOnce(ctx); err != nil {
				logger.Error(err, "status patch failed")
			}
		}
	}
}

// emitOnce walks every active CR rule and patches that CR's
// status.nodeStatus with the writer's row. Errors are returned
// per-tick (not per-CR) so the Run loop can log one line rather than
// spamming one per CR.
func (w *StatusWriter) emitOnce(ctx context.Context) error {
	rules := w.Router.RulesSnapshot()
	stats := w.Router.Stats().snapshot()
	ready := true
	if w.Ready != nil {
		ready = w.Ready()
	}

	var firstErr error
	for _, rule := range rules {
		counters := stats[rule.Key]
		entry := podtracev1alpha1.PodTraceNodeStatus{
			Node:          w.NodeName,
			Ready:         ready,
			ActiveCgroups: lenToInt32(len(rule.CgroupIDs)),
			EventsTotal:   counters.Events,
			DroppedEvents: counters.Dropped,
			LastHeartbeat: metav1.NewTime(time.Now()),
		}
		if err := w.patchCRStatus(ctx, rule.Key, entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (w *StatusWriter) patchCRStatus(ctx context.Context, key CRKey, entry podtracev1alpha1.PodTraceNodeStatus) error {
	applyObj := &podtracev1alpha1.PodTrace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: podtracev1alpha1.GroupVersion.String(),
			Kind:       "PodTrace",
		},
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Status: podtracev1alpha1.PodTraceStatus{
			NodeStatus: []podtracev1alpha1.PodTraceNodeStatus{entry},
		},
	}
	return w.Client.Status().Patch(ctx, applyObj,
		client.Apply,
		client.FieldOwner("podtrace-agent-"+w.NodeName),
		client.ForceOwnership,
	)
}

// ComputeNodeReport assembles the aggregate counters a liveness
// handler might expose. Split out so the probes package and the
// /metrics server can share the same view without duplicating the
// snapshotting code.
func ComputeNodeReport(nodeName string, router *Router, ready bool) NodeReport {
	rules := router.RulesSnapshot()
	stats := router.Stats().snapshot()

	var totalCgroups int32
	var totalEvents, totalDropped int64
	seen := map[uint64]struct{}{}
	for _, rule := range rules {
		for id := range rule.CgroupIDs {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				totalCgroups++
			}
		}
		c := stats[rule.Key]
		totalEvents += c.Events
		totalDropped += c.Dropped
	}
	return NodeReport{
		Node:          nodeName,
		Ready:         ready,
		ActiveCgroups: totalCgroups,
		EventsTotal:   totalEvents,
		DroppedEvents: totalDropped,
		LastHeartbeat: time.Now(),
	}
}

// compile-time assertion we do not accidentally lose thread-safety by
// adding a mutable field.
var _ sync.Locker = (*sync.Mutex)(nil)