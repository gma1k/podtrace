package kubernetes

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestEventsCorrelator_Start_Forbidden(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	clientset.PrependWatchReactor("events", func(k8stesting.Action) (bool, watch.Interface, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "", Resource: "events"},
			"",
			nil,
		)
	})

	correlator := NewEventsCorrelator(clientset, "test-pod", "o11y")
	err := correlator.Start(context.Background())
	if err == nil {
		t.Fatal("expected a forbidden error from Start(), got nil")
	}
	if !IsPermissionError(err) {
		t.Errorf("IsPermissionError(%v) = false, want true", err)
	}
}

func TestIsPermissionError(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "events"}, "", nil)
	if !IsPermissionError(forbidden) {
		t.Error("expected forbidden error to be classified as a permission error")
	}
	if IsPermissionError(apierrors.NewNotFound(schema.GroupResource{Resource: "events"}, "x")) {
		t.Error("not-found error must not be classified as a permission error")
	}
	if IsPermissionError(nil) {
		t.Error("nil must not be classified as a permission error")
	}
}

func TestNewEventsCorrelator(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	correlator := NewEventsCorrelator(clientset, "test-pod", "default")
	
	if correlator == nil {
		t.Fatal("NewEventsCorrelator returned nil")
	}
	if correlator.clientset != clientset {
		t.Error("Expected clientset to be set")
	}
	if correlator.podName != "test-pod" {
		t.Errorf("Expected podName 'test-pod', got %q", correlator.podName)
	}
	if correlator.namespace != "default" {
		t.Errorf("Expected namespace 'default', got %q", correlator.namespace)
	}
	if correlator.events == nil {
		t.Error("Expected events slice to be initialized")
	}
	if correlator.stopCh == nil {
		t.Error("Expected stopCh to be initialized")
	}
}

func TestEventsCorrelator_Start_NilClientset(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	err := correlator.Start(context.Background())
	if err != nil {
		t.Errorf("Start() should return nil for nil clientset, got %v", err)
	}
}

func TestEventsCorrelator_Start_WithClientset(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	correlator := NewEventsCorrelator(clientset, "test-pod", "default")
	
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	err := correlator.Start(ctx)
	if err != nil {
		t.Logf("Start() returned error (expected for fake client): %v", err)
	}
	
	correlator.Stop()
}

func TestEventsCorrelator_AddEvent(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-event",
		},
		InvolvedObject: corev1.ObjectReference{
			Name: "test-pod",
		},
		Type:           "Warning",
		Reason:         "Failed",
		Message:        "Test message",
		FirstTimestamp: metav1.NewTime(time.Now()),
		Count:          1,
	}
	
	correlator.addEvent(event)
	
	events := correlator.GetEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
	if events[0].Type != "Warning" {
		t.Errorf("Expected event type 'Warning', got %q", events[0].Type)
	}
	if events[0].Reason != "Failed" {
		t.Errorf("Expected event reason 'Failed', got %q", events[0].Reason)
	}
}

func TestEventsCorrelator_AddEvent_WrongPodName(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	event := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{
			Name: "other-pod",
		},
		Type:           "Warning",
		Reason:         "Failed",
		Message:        "Test message",
		FirstTimestamp: metav1.NewTime(time.Now()),
		Count:          1,
	}
	
	correlator.addEvent(event)
	
	events := correlator.GetEvents()
	if len(events) != 0 {
		t.Errorf("Expected 0 events for wrong pod name, got %d", len(events))
	}
}

func TestEventsCorrelator_AddEvent_MaxEvents(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	for i := 0; i < 150; i++ {
		event := &corev1.Event{
			InvolvedObject: corev1.ObjectReference{
				Name: "test-pod",
			},
			Type:           "Warning",
			Reason:         "Failed",
			Message:        "Test message",
			FirstTimestamp: metav1.NewTime(time.Now()),
			Count:          1,
		}
		correlator.addEvent(event)
	}
	
	events := correlator.GetEvents()
	if len(events) > 100 {
		t.Errorf("Expected max 100 events, got %d", len(events))
	}
}

func TestEventsCorrelator_GetEvents(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	event := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{
			Name: "test-pod",
		},
		Type:           "Warning",
		Reason:         "Failed",
		Message:        "Test message",
		FirstTimestamp: metav1.NewTime(time.Now()),
		Count:          1,
	}
	
	correlator.addEvent(event)
	
	events := correlator.GetEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
	
	events2 := correlator.GetEvents()
	if len(events2) != 1 {
		t.Errorf("Expected 1 event on second call, got %d", len(events2))
	}
	if len(events) > 0 && len(events2) > 0 && events2[0].Type != events[0].Type {
		t.Error("GetEvents() should return events with same content")
	}
}

func TestEventsCorrelator_Stop(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	correlator.Stop()
	
	select {
	case <-correlator.stopCh:
	default:
		t.Error("Expected stopCh to be closed after Stop()")
	}
}

func TestEventsCorrelator_CorrelateWithAppEvents(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	now := time.Now()
	event1 := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{
			Name: "test-pod",
		},
		Type:           "Warning",
		Reason:         "Failed",
		Message:        "Test message 1",
		FirstTimestamp: metav1.NewTime(now.Add(-5 * time.Second)),
		Count:          1,
	}
	event2 := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{
			Name: "test-pod",
		},
		Type:           "Warning",
		Reason:         "Failed",
		Message:        "Test message 2",
		FirstTimestamp: metav1.NewTime(now.Add(5 * time.Second)),
		Count:          1,
	}
	event3 := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{
			Name: "test-pod",
		},
		Type:           "Warning",
		Reason:         "Failed",
		Message:        "Test message 3",
		FirstTimestamp: metav1.NewTime(now.Add(20 * time.Second)),
		Count:          1,
	}
	
	correlator.addEvent(event1)
	correlator.addEvent(event2)
	correlator.addEvent(event3)
	
	correlated := correlator.CorrelateWithAppEvents(now, 10*time.Second)
	if len(correlated) != 2 {
		t.Errorf("Expected 2 correlated events, got %d", len(correlated))
	}
}

func TestEventsCorrelator_CorrelateWithAppEvents_NoMatches(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	now := time.Now()
	event := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{
			Name: "test-pod",
		},
		Type:           "Warning",
		Reason:         "Failed",
		Message:        "Test message",
		FirstTimestamp: metav1.NewTime(now.Add(-30 * time.Second)),
		Count:          1,
	}
	
	correlator.addEvent(event)
	
	correlated := correlator.CorrelateWithAppEvents(now, 10*time.Second)
	if len(correlated) != 0 {
		t.Errorf("Expected 0 correlated events, got %d", len(correlated))
	}
}

func TestEventsCorrelator_CorrelateWithAppEvents_EmptyEvents(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	
	correlated := correlator.CorrelateWithAppEvents(time.Now(), 10*time.Second)
	if len(correlated) != 0 {
		t.Errorf("Expected 0 correlated events, got %d", len(correlated))
	}
}


// TestEventsCorrelator_AddEvent_EventTimeFallback is a regression guard for the
// events.k8s.io/v1 event shape: those events carry EventTime (a MicroTime) and
// leave FirstTimestamp zero. Before the fix addEvent recorded a zero Timestamp,
// which CorrelateWithAppEvents then filtered out of every time window.
func TestEventsCorrelator_AddEvent_EventTimeFallback(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")
	when := time.Now()

	event := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{Name: "test-pod"},
		Type:           "Warning",
		Reason:         "BackOff",
		Message:        "restarting",
		// No FirstTimestamp: only EventTime, as the v1 events API emits.
		EventTime: metav1.NewMicroTime(when),
	}

	correlator.addEvent(event)

	events := correlator.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Timestamp.IsZero() {
		t.Fatal("EventTime-only event recorded a zero Timestamp; it would be dropped by correlation")
	}
	correlated := correlator.CorrelateWithAppEvents(when, time.Second)
	if len(correlated) != 1 {
		t.Fatalf("EventTime-only event must correlate within the window, got %d", len(correlated))
	}
}

// TestEventsCorrelator_AddEvent_SeriesCount guards the Count fallback: v1
// aggregated events keep the repeat count in Series.Count, not the deprecated
// top-level Count.
func TestEventsCorrelator_AddEvent_SeriesCount(t *testing.T) {
	correlator := NewEventsCorrelator(nil, "test-pod", "default")

	event := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{Name: "test-pod"},
		Type:           "Warning",
		Reason:         "BackOff",
		EventTime:      metav1.NewMicroTime(time.Now()),
		Series:         &corev1.EventSeries{Count: 7},
	}

	correlator.addEvent(event)

	events := correlator.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Count != 7 {
		t.Errorf("expected Count 7 from Series.Count, got %d", events[0].Count)
	}
}
