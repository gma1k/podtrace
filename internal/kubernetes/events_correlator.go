package kubernetes

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

type K8sEvent struct {
	Type      string
	Reason    string
	Message   string
	Timestamp time.Time
	Count     int32
}

// rewatchBackoff is how long the correlator waits before re-establishing
// a watch the API server closed.
var rewatchBackoff = 2 * time.Second

type EventsCorrelator struct {
	clientset kubernetes.Interface
	podName   string
	namespace string
	events    []*K8sEvent
	mu        sync.RWMutex

	eventWatcher watch.Interface
	lastRV       string

	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewEventsCorrelator(clientset kubernetes.Interface, podName, namespace string) *EventsCorrelator {
	return &EventsCorrelator{
		clientset: clientset,
		podName:   podName,
		namespace: namespace,
		events:    make([]*K8sEvent, 0),
		stopCh:    make(chan struct{}),
	}
}

func IsPermissionError(err error) bool {
	return apierrors.IsForbidden(err)
}

func (ec *EventsCorrelator) Start(ctx context.Context) error {
	if ec.clientset == nil {
		return nil
	}

	watcher, err := ec.watch(ctx, "")
	if err != nil {
		return err
	}
	ec.setWatcher(watcher)

	go ec.watchEvents(ctx)
	return nil
}

func (ec *EventsCorrelator) watch(ctx context.Context, resourceVersion string) (watch.Interface, error) {
	return ec.clientset.CoreV1().Events(ec.namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector:   "involvedObject.name=" + ec.podName,
		ResourceVersion: resourceVersion,
	})
}

func (ec *EventsCorrelator) setWatcher(w watch.Interface) {
	ec.mu.Lock()
	ec.eventWatcher = w
	ec.mu.Unlock()
}

func (ec *EventsCorrelator) currentWatcher() watch.Interface {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.eventWatcher
}

// watchEvents consumes the watch channel and re-establishes the watch
// whenever the server closes it, resuming from the last seen
// resourceVersion.
func (ec *EventsCorrelator) watchEvents(ctx context.Context) {
	defer func() {
		if w := ec.currentWatcher(); w != nil {
			w.Stop()
		}
	}()

	for {
		w := ec.currentWatcher()
		if w == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ec.stopCh:
			return
		case event, ok := <-w.ResultChan():
			if !ok {
				if !ec.rewatch(ctx) {
					return
				}
				continue
			}

			if k8sEvent, ok := event.Object.(*corev1.Event); ok {
				ec.mu.Lock()
				ec.lastRV = k8sEvent.ResourceVersion
				ec.mu.Unlock()
				ec.addEvent(k8sEvent)
			}
		}
	}
}

// rewatch replaces the closed watcher, retrying with backoff until it
// succeeds or the correlator is stopped. A "resource version too old"
// rejection falls back to a fresh watch.
func (ec *EventsCorrelator) rewatch(ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ec.stopCh:
			return false
		case <-time.After(rewatchBackoff):
		}

		ec.mu.RLock()
		rv := ec.lastRV
		ec.mu.RUnlock()

		w, err := ec.watch(ctx, rv)
		if err != nil && rv != "" && apierrors.IsResourceExpired(err) {
			w, err = ec.watch(ctx, "")
		}
		if err != nil {
			continue
		}
		ec.setWatcher(w)
		return true
	}
}

func (ec *EventsCorrelator) addEvent(event *corev1.Event) {
	if event.InvolvedObject.Name != ec.podName {
		return
	}

	ec.mu.Lock()
	defer ec.mu.Unlock()

	k8sEvent := &K8sEvent{
		Type:      event.Type,
		Reason:    event.Reason,
		Message:   event.Message,
		Timestamp: event.FirstTimestamp.Time,
		Count:     event.Count,
	}

	ec.events = append(ec.events, k8sEvent)

	maxEvents := 100
	if len(ec.events) > maxEvents {
		ec.events = ec.events[len(ec.events)-maxEvents:]
	}
}

func (ec *EventsCorrelator) GetEvents() []*K8sEvent {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	result := make([]*K8sEvent, len(ec.events))
	copy(result, ec.events)
	return result
}

// Stop is idempotent: a second call is a no-op instead of a panic on the
// already-closed channel.
func (ec *EventsCorrelator) Stop() {
	ec.stopOnce.Do(func() {
		close(ec.stopCh)
		if w := ec.currentWatcher(); w != nil {
			w.Stop()
		}
	})
}

func (ec *EventsCorrelator) CorrelateWithAppEvents(appEventTime time.Time, window time.Duration) []*K8sEvent {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	var correlated []*K8sEvent
	windowStart := appEventTime.Add(-window)
	windowEnd := appEventTime.Add(window)

	for _, k8sEvent := range ec.events {
		if k8sEvent.Timestamp.After(windowStart) && k8sEvent.Timestamp.Before(windowEnd) {
			correlated = append(correlated, k8sEvent)
		}
	}

	return correlated
}
