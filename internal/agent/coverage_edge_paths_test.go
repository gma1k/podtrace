package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/tracer"
)

func TestDeploymentNameSurvivesEveryPodTemplateHashCharacter(t *testing.T) {
	for _, chunk := range []string{
		"0123456789",
		"bcdfghjkmn",
		"pqrstvwxyz",
		"jkmn7",
		"pqrst",
		"vwxyz",
	} {
		name, ok := deploymentFromReplicaSet("checkout-" + chunk)
		if !ok || name != "checkout" {
			t.Errorf("deploymentFromReplicaSet(checkout-%s) = %q, %v; want checkout, true. "+
				"kube-controller-manager mints the suffix from this alphabet, and a character "+
				"it rejects leaves the workload labelled by ReplicaSet, which changes on every "+
				"rollout and breaks continuity of every series keyed on workload", chunk, name, ok)
		}
	}
}

func TestAReplicaSetSuffixOutsideTheAlphabetIsNotAHash(t *testing.T) {
	for _, suffix := range []string{"aeiou", "ABCDE", "12-45", "abc", strings.Repeat("b", 13)} {
		if name, ok := deploymentFromReplicaSet("checkout-" + suffix); ok {
			t.Errorf("deploymentFromReplicaSet(checkout-%s) = %q, true; want false. A name that "+
				"merely contains a dash is not a ReplicaSet suffix, and trimming it would "+
				"report a workload that does not exist", suffix, name)
		}
	}
}

func TestARuleWithNoExporterIsSkippedRatherThanCounted(t *testing.T) {
	stats := newPerCRStats()
	router := NewRouter(stats)
	key := CRKey{Namespace: "shop", Name: "no-exporter"}
	router.Publish([]CRRule{{
		Key:       key,
		Exporter:  nil,
		CgroupIDs: map[uint64]struct{}{42: {}},
		Filters:   map[events.EventType]struct{}{events.EventTCPSend: {}},
	}}).Wait()

	batch := []*events.Event{{Type: events.EventTCPSend, CgroupID: 42}}
	if err := router.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	counts := stats.snapshot()
	if counted, present := counts[key]; present && (counted.Events > 0 || counted.Dropped > 0) {
		t.Errorf("rule %v counted %+v with no exporter attached. A CR whose exporter failed to "+
			"build must not read as delivering telemetry", key, counted)
	}
}

func TestTargetsAreDroppedRatherThanBlockingTheReconciler(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	r := &AgentReconciler{
		Client:        c,
		NodeName:      "n",
		Router:        NewRouter(nil),
		TargetsCh:     make(chan tracer.TargetSet),
		exporterCache: map[CRKey]cachedExporter{},
	}

	done := make(chan error, 1)
	go func() {
		_, err := r.Reconcile(context.Background(), ctrl.Request{})
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	case <-contextTimeout():
		t.Fatal("Reconcile blocked publishing targets with no reader attached. The reconciler " +
			"runs on the controller's worker, so blocking there stalls every later pod event " +
			"on this node behind it")
	}
}

func TestOTLPEventExporterRefusesABundleWithNoEndpoint(t *testing.T) {
	if _, err := newOTLPEventExporter(CRKey{Name: "cr"}, &BundlePayload{}); err == nil {
		t.Fatal("a bundle with no endpoint built an exporter. Spans would be handed to a client " +
			"addressed nowhere and dropped without an error the operator can see")
	}
}

func TestOTLPEventExporterRefusesAnUnparseableEndpoint(t *testing.T) {
	if _, err := newOTLPEventExporter(CRKey{Name: "cr"}, &BundlePayload{Endpoint: "://nope"}); err == nil {
		t.Fatal("an unparseable endpoint built an exporter")
	}
}

func contextTimeout() <-chan struct{} {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = cancel
	return ctx.Done()
}

func TestAShutdownDuringCacheSyncIsNotAFailure(t *testing.T) {
	if err := cacheSyncError(false, context.Canceled); err != nil {
		t.Errorf("cacheSyncError(false, canceled) = %v, want nil. A pod terminated before its "+
			"informers finished syncing exits non-zero otherwise, which reads as a crash loop "+
			"during an ordinary rollout", err)
	}
	if err := cacheSyncError(false, context.DeadlineExceeded); err != nil {
		t.Errorf("cacheSyncError(false, deadline) = %v, want nil", err)
	}
}

func TestAGenuineCacheSyncFailureIsReported(t *testing.T) {
	if err := cacheSyncError(false, nil); err == nil {
		t.Error("a cache that failed to sync with a live context reported success. The agent " +
			"would mark itself ready and serve an empty view of the cluster")
	}
	if err := cacheSyncError(true, nil); err != nil {
		t.Errorf("cacheSyncError(true, nil) = %v, want nil", err)
	}
}
