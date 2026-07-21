package agent

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

func TestAppendWorkloadAttributes_EmptyNameIsNoop(t *testing.T) {
	base := []attribute.KeyValue{attribute.String("keep", "me")}

	got := appendWorkloadAttributes(base, "Deployment", "")
	if len(got) != len(base) {
		t.Errorf("empty name should append nothing, got %d attrs (want %d)", len(got), len(base))
	}

	if got := appendWorkloadAttributes(base, "", ""); len(got) != len(base) {
		t.Errorf("empty kind+name should append nothing, got %d attrs", len(got))
	}
}

func TestAppendWorkloadAttributes_DeploymentSpecificKey(t *testing.T) {
	got := appendWorkloadAttributes(nil, "Deployment", "web")
	found := false
	for _, kv := range got {
		if string(kv.Key) == "k8s.deployment.name" && kv.Value.AsString() == "web" {
			found = true
		}
		if string(kv.Key) == "k8s.workload.kind" {
			t.Error("Deployment must not fall through to the generic k8s.workload.kind key")
		}
	}
	if !found {
		t.Errorf("expected k8s.deployment.name=web, got %+v", got)
	}
}
