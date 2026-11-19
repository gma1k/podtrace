package operator

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPublishSessionSecretReport_IgnoresServiceAccountTokenStaging(t *testing.T) {
	s := secretReportSession()
	forged := stagedReport(s, "n1", "")
	forged.Type = corev1.SecretTypeServiceAccountToken
	forged.Annotations = map[string]string{corev1.ServiceAccountNameKey: "podtrace-operator"}
	forged.Data = map[string][]byte{"token": []byte("operator-token"), "ca.crt": []byte("ca"), "namespace": []byte(sessMoreSysNS)}
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(forged, stagedReport(s, "n2", "two")).Build()

	if err := publishSessionSecretReport(context.Background(), c, c, s, []string{sessMoreSysNS}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	var report corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &report); err != nil {
		t.Fatalf("tenant report Secret: %v", err)
	}
	if len(report.Data) != 1 || string(report.Data["report-n2.txt"]) != "two" {
		t.Fatalf("report data = %v, want only the report of n2", report.Data)
	}
	var left corev1.SecretList
	if err := c.List(context.Background(), &left, client.MatchingLabels(reportStagingLabels(s))); err != nil {
		t.Fatal(err)
	}
	if len(left.Items) != 0 {
		t.Errorf("%d staging Secret(s) left, want the forged one deleted too", len(left.Items))
	}
}

func TestPublishSessionSecretReport_OnlyForgedStagingPublishesNothing(t *testing.T) {
	s := secretReportSession()
	forged := stagedReport(s, "n1", "")
	forged.Type = corev1.SecretTypeServiceAccountToken
	forged.Data = map[string][]byte{"token": []byte("operator-token")}
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(forged).Build()

	err := publishSessionSecretReport(context.Background(), c, c, s, []string{sessMoreSysNS})
	if !errors.Is(err, errNothingStaged) {
		t.Fatalf("publish err = %v, want errNothingStaged", err)
	}
	var report corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &report); err == nil {
		t.Fatalf("a tenant Secret was published from a forged staging Secret: %v", report.Data)
	}
}

func TestStagedReportData_KeepsOnlyReportKeys(t *testing.T) {
	staged := &corev1.Secret{Data: map[string][]byte{
		"report-n1.txt": []byte("one"),
		"report.txt":    []byte("bare"),
		"report-.txt":   []byte("no node"),
		"report-n1.log": []byte("wrong suffix"),
		"token":         []byte("secret"),
	}}
	got := stagedReportData(staged)
	if len(got) != 2 || string(got["report-n1.txt"]) != "one" || string(got["report.txt"]) != "bare" {
		t.Fatalf("stagedReportData = %v, want report-n1.txt and report.txt only", got)
	}
}

func TestStagedReportData_RefusesNonOpaqueTypes(t *testing.T) {
	for _, typ := range []corev1.SecretType{corev1.SecretTypeServiceAccountToken, corev1.SecretTypeDockerConfigJson, corev1.SecretTypeTLS} {
		staged := &corev1.Secret{Type: typ, Data: map[string][]byte{"report-n1.txt": []byte("one")}}
		if got := stagedReportData(staged); len(got) != 0 {
			t.Errorf("type %s: stagedReportData = %v, want nothing", typ, got)
		}
	}
}
