package kubernetes

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestADeploymentPodIsAttributedToItsDeploymentLikeTheAgent(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)
	controller := true
	pod := runningPod("uid-dep", "prod", "api-5c4b6d7f9-x2k4p", "app", cid)
	pod.OwnerReferences = []metav1.OwnerReference{
		{Kind: "Node", Name: "worker-1"},
		{Kind: "ReplicaSet", Name: "api-5c4b6d7f9", Controller: &controller},
	}

	fromObject, err := resolvePodInfoFromObject(context.Background(), pod, "")
	if err != nil {
		t.Fatal(err)
	}
	fromResolver, err := NewPodResolverForTesting(fake.NewClientset(pod)).ResolvePod(context.Background(), pod.Name, pod.Namespace, "")
	if err != nil {
		t.Fatal(err)
	}
	for source, info := range map[string]*PodInfo{"registry": fromObject, "resolver": fromResolver} {
		if info.OwnerKind != "Deployment" || info.OwnerName != "api" {
			t.Errorf("%s owner = %s/%s, want Deployment/api", source, info.OwnerKind, info.OwnerName)
		}
	}
}
