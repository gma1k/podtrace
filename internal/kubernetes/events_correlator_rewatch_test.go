package kubernetes

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestRewatch_ContextCancelled(t *testing.T) {
	ec := NewEventsCorrelator(fake.NewSimpleClientset(), "p", "ns")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ec.rewatch(ctx) {
		t.Error("rewatch must return false when the context is cancelled")
	}
}

func TestRewatch_StopCh(t *testing.T) {
	ec := NewEventsCorrelator(fake.NewSimpleClientset(), "p", "ns")
	close(ec.stopCh)
	if ec.rewatch(context.Background()) {
		t.Error("rewatch must return false when stopCh is closed")
	}
}

func TestRewatch_Success(t *testing.T) {
	orig := rewatchBackoff
	rewatchBackoff = time.Millisecond
	t.Cleanup(func() { rewatchBackoff = orig })

	ec := NewEventsCorrelator(fake.NewSimpleClientset(), "p", "ns")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if !ec.rewatch(ctx) {
		t.Fatal("expected rewatch to succeed against the fake clientset")
	}
	if ec.currentWatcher() == nil {
		t.Error("expected a new watcher to be installed after a successful rewatch")
	}
	ec.Stop()
}

func TestRewatch_ResourceExpiredFallsBackToFreshWatch(t *testing.T) {
	orig := rewatchBackoff
	rewatchBackoff = time.Millisecond
	t.Cleanup(func() { rewatchBackoff = orig })

	clientset := fake.NewSimpleClientset()
	fresh := watch.NewRaceFreeFake()
	clientset.PrependWatchReactor("events", func(action k8stesting.Action) (bool, watch.Interface, error) {
		wa, ok := action.(k8stesting.WatchAction)
		if ok && wa.GetWatchRestrictions().ResourceVersion == "999" {
			return true, nil, apierrors.NewResourceExpired("resource version 999 too old")
		}
		return true, fresh, nil
	})

	ec := NewEventsCorrelator(clientset, "p", "ns")
	ec.lastRV = "999"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !ec.rewatch(ctx) {
		t.Fatal("expected rewatch to recover via a fresh watch after a ResourceExpired error")
	}
	ec.Stop()
}
