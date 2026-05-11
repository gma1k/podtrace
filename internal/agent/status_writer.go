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

const DefaultStatusReportInterval = 30 * time.Second

type StatusWriter struct {
	Client   client.Client
	NodeName string
	Interval time.Duration
	Router   *Router

	Ready func() bool
}

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

func (w *StatusWriter) emitOnce(ctx context.Context) error {
	rules := w.Router.RulesSnapshot()
	stats := w.Router.Stats().snapshot()
	agentReady := true
	if w.Ready != nil {
		agentReady = w.Ready()
	}

	var firstErr error
	for _, rule := range rules {
		entry := buildNodeStatusEntry(w.NodeName, &rule, stats[rule.Key], agentReady, time.Now())
		if err := w.patchCRStatus(ctx, rule.Key, entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func buildNodeStatusEntry(node string, rule *CRRule, counters crCounters, agentReady bool, now time.Time) podtracev1alpha1.PodTraceNodeStatus {
	entry := podtracev1alpha1.PodTraceNodeStatus{
		Node:          node,
		Ready:         agentReady && rule.Err == nil,
		ActiveCgroups: lenToInt32(len(rule.CgroupIDs)),
		EventsTotal:   counters.Events,
		DroppedEvents: counters.Dropped,
		LastHeartbeat: metav1.NewTime(now),
	}
	if rule.Err != nil {
		entry.Message = rule.Err.Error()
	}
	return entry
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

var _ sync.Locker = (*sync.Mutex)(nil)