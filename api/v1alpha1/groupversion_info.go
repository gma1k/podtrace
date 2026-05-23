// Package v1alpha1 contains API Schema definitions for the podtrace.io v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=podtrace.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion = schema.GroupVersion{Group: "podtrace.io", Version: "v1alpha1"}

	SchemeGroupVersion = GroupVersion

	SchemeBuilder runtime.SchemeBuilder

	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		metav1.AddToGroupVersion(s, GroupVersion)
		return nil
	})
}

// Resource takes an unqualified resource name and returns a GroupResource
// for the podtrace.io/v1alpha1 API group. Referenced by generated client code.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

func addKnownTypes(objs ...runtime.Object) func(*runtime.Scheme) error {
	return func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, objs...)
		return nil
	}
}
