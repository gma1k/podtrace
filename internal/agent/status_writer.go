package agent

import (
	"context"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	podtraceac "github.com/podtrace/podtrace/pkg/client/applyconfiguration/api/v1alpha1"
)

const DefaultStatusReportInterval = 30 * time.Second

type StatusWriter struct {
	Client   client.Client
	NodeName string
	Interval time.Duration
	Router   *Router

	Ready     func() bool
	Heartbeat func()

	BackendErr error
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
	if w.Heartbeat != nil {
		w.Heartbeat()
	}

	rules := w.Router.RulesSnapshot()
	stats := w.Router.Stats().snapshot()
	agentReady := true
	if w.Ready != nil {
		agentReady = w.Ready()
	}

	var firstErr error
	for _, rule := range rules {
		entry := buildNodeStatusEntry(w.NodeName, &rule, stats[rule.Key], agentReady, w.BackendErr, time.Now())
		if err := w.patchCRStatus(ctx, rule.Key, entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func buildNodeStatusEntry(node string, rule *CRRule, counters crCounters, agentReady bool, backendErr error, now time.Time) podtracev1alpha1.PodTraceNodeStatus {
	entry := podtracev1alpha1.PodTraceNodeStatus{
		Node:          node,
		Ready:         agentReady && rule.Err == nil && backendErr == nil,
		MatchedPods:   rule.MatchedPods,
		ActiveCgroups: lenToInt32(len(rule.CgroupIDs)),
		EventsTotal:   counters.Events,
		DroppedEvents: counters.Dropped,
		LastHeartbeat: metav1.NewTime(now),
		PolicyHash:    rule.Policy.Hash,
	}
	switch {
	case backendErr != nil:
		entry.Message = "tracer backend unavailable: " + backendErr.Error()
		entry.Reason = podtracev1alpha1.NodeStatusReasonBackendUnavailable
	case rule.Err != nil:
		entry.Message = rule.Err.Error()
		entry.Reason = classifyRuleErr(rule.Err)
	case !agentReady:
		entry.Message = "agent not ready"
		entry.Reason = podtracev1alpha1.NodeStatusReasonAgentUnready
	}
	return entry
}

func classifyRuleErr(err error) podtracev1alpha1.NodeStatusReason {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "load bundle"):
		return podtracev1alpha1.NodeStatusReasonBundleLoadFailed
	case strings.HasPrefix(msg, "match pods"):
		return podtracev1alpha1.NodeStatusReasonPodMatchFailed
	case strings.HasPrefix(msg, "resolve cgroup IDs"):
		return podtracev1alpha1.NodeStatusReasonCgroupResolutionFailed
	case strings.HasPrefix(msg, "build exporter"):
		return podtracev1alpha1.NodeStatusReasonExporterBuildFailed
	case strings.Contains(msg, "policy"):
		return podtracev1alpha1.NodeStatusReasonPolicyParseError
	}
	return podtracev1alpha1.NodeStatusReasonUnknown
}

func (w *StatusWriter) patchCRStatus(ctx context.Context, key CRKey, entry podtracev1alpha1.PodTraceNodeStatus) error {
	nodeAC := podtraceac.PodTraceNodeStatus().
		WithNode(entry.Node).
		WithReady(entry.Ready).
		WithMatchedPods(entry.MatchedPods).
		WithActiveCgroups(entry.ActiveCgroups).
		WithEventsTotal(entry.EventsTotal).
		WithDroppedEvents(entry.DroppedEvents).
		WithLastHeartbeat(entry.LastHeartbeat).
		WithPolicyHash(entry.PolicyHash)
	if entry.Message != "" {
		nodeAC = nodeAC.WithMessage(entry.Message)
	}
	if entry.Reason != "" {
		nodeAC = nodeAC.WithReason(entry.Reason)
	}
	applyConfig := podtraceac.PodTrace(key.Name, key.Namespace).
		WithStatus(podtraceac.PodTraceStatus().WithNodeStatus(nodeAC))
	return w.Client.Status().Apply(ctx, applyConfig,
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
