// Package v1alpha1 contains API Schema definitions for the podtrace.io v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=podtrace.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion = schema.GroupVersion{Group: "podtrace.io", Version: "v1alpha1"}

	// SchemeGroupVersion is an alias for GroupVersion, exposed for
	// compatibility with k8s.io/code-generator's client-gen output, which
	// expects this identifier on the API package.
	SchemeGroupVersion = GroupVersion

	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	AddToScheme = SchemeBuilder.AddToScheme
)

// Resource takes an unqualified resource name and returns a GroupResource
// for the podtrace.io/v1alpha1 API group. Referenced by generated client code.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
