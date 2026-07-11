package main

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestReportDataKey_PerNode(t *testing.T) {
	t.Setenv("NODE_NAME", "")
	if got := reportDataKey(); got != "report.txt" {
		t.Errorf("no NODE_NAME: got %q want report.txt", got)
	}
	t.Setenv("NODE_NAME", "kind-worker-2")
	if got := reportDataKey(); got != "report-kind-worker-2.txt" {
		t.Errorf("with NODE_NAME: got %q want report-kind-worker-2.txt", got)
	}
	t.Setenv("NODE_NAME", "weird/node name")
	if got := reportDataKey(); got != "report-weird-node-name.txt" {
		t.Errorf("sanitized key: got %q want report-weird-node-name.txt", got)
	}
}

func TestUpsertReportConfigMap_PerNodeKeysCoexist(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx := context.Background()

	if err := upsertReportConfigMap(ctx, client, "ns", "rpt", "report-node-a.txt", "A"); err != nil {
		t.Fatal(err)
	}
	if err := upsertReportConfigMap(ctx, client, "ns", "rpt", "report-node-b.txt", "B"); err != nil {
		t.Fatal(err)
	}

	cm, err := client.CoreV1().ConfigMaps("ns").Get(ctx, "rpt", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cm.Data["report-node-a.txt"] != "A" || cm.Data["report-node-b.txt"] != "B" {
		t.Errorf("per-node reports clobbered each other: %+v", cm.Data)
	}
}
