package events

import "testing"

func TestK8sMetadata_IsZero(t *testing.T) {
	tests := []struct {
		name string
		meta K8sMetadata
		want bool
	}{
		{"empty", K8sMetadata{}, true},
		{"namespace set", K8sMetadata{Namespace: "default"}, false},
		{"pod name set", K8sMetadata{PodName: "p"}, false},
		{"pod uid set", K8sMetadata{PodUID: "uid"}, false},
		{"node name set", K8sMetadata{NodeName: "node1"}, false},
		{"container name set", K8sMetadata{ContainerName: "c"}, false},
		{"workload kind set", K8sMetadata{WorkloadKind: "Deployment"}, false},
		{"workload name set", K8sMetadata{WorkloadName: "web"}, false},
		{"fully populated", K8sMetadata{
			Namespace:     "default",
			PodName:       "p",
			PodUID:        "uid",
			NodeName:      "node1",
			ContainerName: "c",
			WorkloadKind:  "Deployment",
			WorkloadName:  "web",
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.meta.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}
