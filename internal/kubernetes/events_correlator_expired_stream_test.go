package kubernetes

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func podEvent(uid, rv, reason string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{UID: types.UID(uid), ResourceVersion: rv, Name: uid, Namespace: "ns"},
		InvolvedObject: corev1.ObjectReference{Name: "p"},
		Reason:         reason,
		FirstTimestamp: metav1.NewTime(time.Unix(1000, 0)),
	}
}

func TestAnInStreamGoneErrorResumesFromAFreshWatch(t *testing.T) {
	orig := rewatchBackoff
	rewatchBackoff = time.Millisecond
	t.Cleanup(func() { rewatchBackoff = orig })

	first := watch.NewRaceFreeFake()
	fresh := watch.NewRaceFreeFake()
	var mu sync.Mutex
	var requested []string
	clientset := fake.NewSimpleClientset()
	clientset.PrependWatchReactor("events", func(action k8stesting.Action) (bool, watch.Interface, error) {
		rv := action.(k8stesting.WatchAction).GetWatchRestrictions().ResourceVersion
		mu.Lock()
		defer mu.Unlock()
		requested = append(requested, rv)
		switch {
		case len(requested) == 1:
			return true, first, nil
		case rv == "":
			return true, fresh, nil
		default:
			return true, watch.NewRaceFreeFake(), nil
		}
	})

	ec := NewEventsCorrelator(clientset, "p", "ns")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ec.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ec.Stop()

	first.Add(podEvent("e1", "10", "Pulled"))
	first.Error(&metav1.Status{Status: metav1.StatusFailure, Code: http.StatusGone, Reason: metav1.StatusReasonExpired, Message: "too old resource version: 10"})
	first.Stop()

	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := len(requested)
		last := ""
		if n > 0 {
			last = requested[n-1]
		}
		mu.Unlock()
		if n >= 2 {
			if last != "" {
				t.Fatalf("rewatch reopened at stale resourceVersion %q after a 410 Gone; want a fresh watch", last)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("no rewatch happened")
		case <-time.After(5 * time.Millisecond):
		}
	}

	fresh.Add(podEvent("e1", "10", "Pulled"))
	fresh.Add(podEvent("e2", "20", "Killing"))
	deadline = time.After(3 * time.Second)
	for len(ec.GetEvents()) < 2 {
		select {
		case <-deadline:
			t.Fatalf("events = %d, want 2", len(ec.GetEvents()))
		case <-time.After(5 * time.Millisecond):
		}
	}
	time.Sleep(20 * time.Millisecond)
	got := ec.GetEvents()
	if len(got) != 2 || got[0].Reason != "Pulled" || got[1].Reason != "Killing" {
		t.Fatalf("events = %+v, want Pulled then Killing once each (the fresh watch replays e1)", got)
	}
}

func TestANonExpiryWatchErrorKeepsTheResumePoint(t *testing.T) {
	ec := NewEventsCorrelator(fake.NewSimpleClientset(), "p", "ns")
	ec.lastRV = "42"
	ec.handleWatchError(&metav1.Status{Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError})
	if ec.lastRV != "42" {
		t.Fatalf("lastRV = %q, want 42 kept for a transient error", ec.lastRV)
	}
}

func TestAModifiedEventIsStillRecorded(t *testing.T) {
	ec := NewEventsCorrelator(fake.NewSimpleClientset(), "p", "ns")
	ec.addEvent(podEvent("e1", "1", "BackOff"))
	ec.addEvent(podEvent("e1", "1", "BackOff"))
	ec.addEvent(podEvent("e1", "2", "BackOff"))
	if n := len(ec.GetEvents()); n != 2 {
		t.Fatalf("events = %d, want 2: a replay is dropped, a new resourceVersion is kept", n)
	}
}

func TestTheSeenSetStaysBounded(t *testing.T) {
	ec := NewEventsCorrelator(fake.NewSimpleClientset(), "p", "ns")
	for i := 0; i < maxSeenEvents*3; i++ {
		ec.addEvent(podEvent(time.Unix(int64(i), 0).String(), "1", "X"))
	}
	if len(ec.seen) > maxSeenEvents {
		t.Fatalf("seen = %d entries, want at most %d", len(ec.seen), maxSeenEvents)
	}
}

func TestAZeroValueCorrelatorRecordsEvents(t *testing.T) {
	ec := &EventsCorrelator{podName: "p"}
	ec.addEvent(podEvent("e1", "1", "Pulled"))
	if n := len(ec.GetEvents()); n != 1 {
		t.Fatalf("events = %d, want 1", n)
	}
}
