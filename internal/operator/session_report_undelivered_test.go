package operator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func emptyStagedReport(s *podtracev1alpha1.PodTraceSession, node string) *corev1.Secret {
	staged := stagedReport(s, node, "")
	staged.Data = nil
	return staged
}

func TestPublishSessionSecretReport_NoDeliveredReportIsNothingStaged(t *testing.T) {
	s := secretReportSession()
	stagingRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}}
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithObjects(emptyStagedReport(s, "n1"), emptyStagedReport(s, "n2"), stagingRole).Build()

	err := publishSessionSecretReport(context.Background(), c, c, s, []string{sessMoreSysNS})

	if !errors.Is(err, errNothingStaged) || !strings.Contains(err.Error(), "no Job delivered its report") {
		t.Fatalf("publish = %v, want NothingStaged for staging Secrets no Job wrote", err)
	}
	var report corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &report); !apierrors.IsNotFound(err) {
		t.Errorf("an empty report Secret was published: %v %v", report.Data, err)
	}
	var left corev1.SecretList
	if err := c.List(context.Background(), &left, client.MatchingLabels(reportStagingLabels(s))); err != nil {
		t.Fatal(err)
	}
	if len(left.Items) != 0 {
		t.Errorf("%d staging Secret(s) left behind", len(left.Items))
	}
	var role rbacv1.Role
	if err := c.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}, &role); err == nil {
		t.Error("the staging Role outlived a session with nothing to publish")
	}
}

func TestPublishSessionSecretReport_StagingDeletedBeforeReadIsNothingStaged(t *testing.T) {
	s := secretReportSession()
	staged := stagedReport(s, "n1", "one")
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(staged).Build()
	reader := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()

	err := publishSessionSecretReport(context.Background(), c, reader, s, []string{sessMoreSysNS})

	if !errors.Is(err, errNothingStaged) {
		t.Fatalf("publish = %v, want NothingStaged when every staging Secret vanished", err)
	}
}

func TestPublishSessionSecretReport_NothingDeliveredCleanupFailureIsReturned(t *testing.T) {
	s := secretReportSession()
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithObjects(emptyStagedReport(s, "n1")).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return errors.New("delete refused")
			},
		}).Build()

	err := publishSessionSecretReport(context.Background(), c, c, s, []string{sessMoreSysNS})

	if err == nil || errors.Is(err, errNothingStaged) {
		t.Fatalf("publish = %v, want the cleanup failure so it is retried", err)
	}
}
