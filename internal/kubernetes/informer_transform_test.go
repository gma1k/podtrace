package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTrimPodForCache_StripsHeavyFieldsKeepsIndexed(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "p",
			Namespace:     "ns",
			Labels:        map[string]string{"app": "x"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
			Annotations:   map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "huge"},
		},
		Spec:   corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "c"}}},
		Status: corev1.PodStatus{PodIP: "10.0.0.5", ContainerStatuses: []corev1.ContainerStatus{{Name: "c"}}},
	}

	out, _ := trimPodForCache(pod)
	got := out.(*corev1.Pod)
	if got.ManagedFields != nil || got.Annotations != nil {
		t.Error("managedFields/annotations must be cleared")
	}
	if len(got.Spec.Containers) != 0 {
		t.Error("spec must be cleared")
	}
	if len(got.Status.ContainerStatuses) != 0 {
		t.Error("status beyond the pod IP must be cleared")
	}
	if got.Status.PodIP != "10.0.0.5" {
		t.Errorf("indexed PodIP must be preserved, got %q", got.Status.PodIP)
	}
	if got.Name != "p" || got.Namespace != "ns" || got.Labels["app"] != "x" {
		t.Errorf("name/namespace/labels must be preserved, got %+v", got.ObjectMeta)
	}

	if passthrough, _ := trimPodForCache("tombstone"); passthrough != "tombstone" {
		t.Error("a non-Pod object must pass through untouched")
	}
}

func TestTrimEndpointSliceForCache_StripsHeavyFieldsKeepsIndexed(t *testing.T) {
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "e",
			Namespace:     "ns",
			Labels:        map[string]string{discoveryv1.LabelServiceName: "svc"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "eps-controller"}},
			Annotations:   map[string]string{"big": "x"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.6"}}},
	}

	out, _ := trimEndpointSliceForCache(es)
	got := out.(*discoveryv1.EndpointSlice)
	if got.ManagedFields != nil || got.Annotations != nil {
		t.Error("managedFields/annotations must be cleared")
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].Addresses[0] != "10.0.0.6" {
		t.Error("indexed endpoints must be preserved")
	}
	if got.Labels[discoveryv1.LabelServiceName] != "svc" {
		t.Error("the service-name label must be preserved")
	}
}
