package podworkload

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The workload a pod belongs to, named the one way every podtrace component
// names it: the agent labels its metrics with it, and the operator maps a
// Service's pods onto it, so the two must never disagree.

// Of walks pod.OwnerReferences and returns the
// (kind, name) of the workload that ultimately produced this pod.
func Of(pod *corev1.Pod) (kind, name string) {
	owner := ControllerOwnerRef(pod.OwnerReferences)
	if owner == nil {
		return "Pod", pod.Name
	}
	if owner.Kind == "ReplicaSet" {
		if deployment, ok := DeploymentFromReplicaSet(owner.Name); ok {
			return "Deployment", deployment
		}
		return "ReplicaSet", owner.Name
	}
	return owner.Kind, owner.Name
}

// ControllerOwnerRef returns the OwnerReference flagged as the
// controller.
func ControllerOwnerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		ref := &refs[i]
		if ref.Controller != nil && *ref.Controller {
			return ref
		}
	}
	return nil
}

// DeploymentFromReplicaSet strips the kubernetes-controller-manager
// pod-template-hash suffix from a ReplicaSet name.
func DeploymentFromReplicaSet(rsName string) (string, bool) {
	idx := strings.LastIndex(rsName, "-")
	if idx < 1 || idx == len(rsName)-1 {
		return "", false
	}
	suffix := rsName[idx+1:]
	if !isPodTemplateHash(suffix) {
		return "", false
	}
	return rsName[:idx], true
}

// isPodTemplateHash matches the alphabet kube-controller-manager
// uses for the ReplicaSet pod-template-hash suffix.
func isPodTemplateHash(s string) bool {
	if len(s) < 5 || len(s) > 12 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c == 'b', c == 'c', c == 'd':
		case c == 'f', c == 'g', c == 'h':
		case c == 'j', c == 'k', c == 'm', c == 'n':
		case c >= 'p' && c <= 't':
		case c == 'v', c == 'w', c == 'x', c == 'y', c == 'z':
		default:
			return false
		}
	}
	return true
}
