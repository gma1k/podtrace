package main

import (
	"reflect"
	"sync"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
)

// maxInternedContexts bounds how many distinct enrichment contexts and pod
// identities are shared.
const maxInternedContexts = 4096

// contextKey is everything a Kubernetes context map is built from. Label maps
// are keyed by identity: the enricher hands out the cached map of a pod, and
// a refreshed pod gets a new map and so a new key.
type contextKey struct {
	sourceNamespace  string
	targetPod        string
	targetService    string
	targetNamespace  string
	serviceNamespace string
	isExternal       bool
	targetLabels     uintptr
	hasSource        bool
	sourcePod        string
	sourcePodNS      string
	sourceLabels     uintptr
	sourceKind       string
	sourceName       string
}

type metadataKey struct {
	namespace string
	pod       string
	container string
}

// contextInterner shares one read-only context map, and one K8sMetadata, among
// all events that would otherwise each carry an identical copy.
type contextInterner struct {
	mu       sync.Mutex
	contexts map[contextKey]map[string]interface{}
	metadata map[metadataKey]*events.K8sMetadata
}

var k8sContexts = &contextInterner{}

func labelsIdentity(m map[string]string) uintptr {
	if m == nil {
		return 0
	}
	return reflect.ValueOf(m).Pointer()
}

func newContextKey(kc *kubernetes.KubernetesContext, sourceNamespace string, source *kubernetes.PodInfo) contextKey {
	k := contextKey{
		sourceNamespace:  sourceNamespace,
		targetPod:        kc.TargetPodName,
		targetService:    kc.ServiceName,
		targetNamespace:  kc.TargetNamespace,
		serviceNamespace: kc.ServiceNamespace,
		isExternal:       kc.IsExternal,
		targetLabels:     labelsIdentity(kc.TargetLabels),
	}
	if source != nil {
		k.hasSource = true
		k.sourcePod = source.PodName
		k.sourcePodNS = source.Namespace
		k.sourceLabels = labelsIdentity(source.Labels)
		k.sourceKind = source.OwnerKind
		k.sourceName = source.OwnerName
	}
	return k
}

// context returns the shared map for key, building it with build the first
// time.
func (in *contextInterner) context(key contextKey, build func() map[string]interface{}) map[string]interface{} {
	in.mu.Lock()
	defer in.mu.Unlock()
	if m, ok := in.contexts[key]; ok {
		return m
	}
	m := build()
	if in.contexts == nil {
		in.contexts = make(map[contextKey]map[string]interface{})
	}
	if len(in.contexts) < maxInternedContexts {
		in.contexts[key] = m
	}
	return m
}

// podMetadata returns the shared K8sMetadata naming a source pod's container.
func (in *contextInterner) podMetadata(namespace, pod, container string) *events.K8sMetadata {
	key := metadataKey{namespace: namespace, pod: pod, container: container}
	in.mu.Lock()
	defer in.mu.Unlock()
	if m, ok := in.metadata[key]; ok {
		return m
	}
	m := &events.K8sMetadata{Namespace: namespace, PodName: pod, ContainerName: container}
	if in.metadata == nil {
		in.metadata = make(map[metadataKey]*events.K8sMetadata)
	}
	if len(in.metadata) < maxInternedContexts {
		in.metadata[key] = m
	}
	return m
}
