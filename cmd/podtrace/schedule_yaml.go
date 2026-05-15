package main

import (
	sigsyaml "sigs.k8s.io/yaml"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// marshalSessionYAML renders a PodTraceSession to the same shape
// kubectl get -o yaml would emit.
func marshalSessionYAML(s *podtracev1alpha1.PodTraceSession) ([]byte, error) {
	s.APIVersion = podtracev1alpha1.GroupVersion.String()
	s.Kind = "PodTraceSession"
	return sigsyaml.Marshal(s)
}