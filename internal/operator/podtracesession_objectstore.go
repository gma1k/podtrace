package operator

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

const reportUploaderContainerName = "report-uploader"

func harvestReportLocation(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) (resolvedURI string, terminated bool, ok bool, err error) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return "", false, false, nil
	}

	var pods corev1.PodList
	if err := c.List(ctx, &pods,
		client.InNamespace(systemNS),
		client.MatchingLabels{
			LabelSessionName: s.Name,
			LabelSessionNS:   s.Namespace,
		},
	); err != nil {
		return "", false, false, fmt.Errorf("list session pods: %w", err)
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, cs := range pod.Status.InitContainerStatuses {
			if cs.Name != reportUploaderContainerName {
				continue
			}
			if cs.State.Terminated == nil {
				continue
			}
			msg := strings.TrimSpace(cs.State.Terminated.Message)
			if cs.State.Terminated.ExitCode == 0 && msg != "" {
				return msg, true, true, nil
			}
			return msg, true, false, nil
		}
	}
	return "", false, false, nil
}

func applyReportUploadStatus(s *podtracev1alpha1.PodTraceSession, uri string, terminated, ok bool) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return
	}
	now := metav1.Now()

	switch {
	case !terminated:
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionReportUploaded,
			Status:             metav1.ConditionUnknown,
			Reason:             "UploadPending",
			Message:            "sidecar has not terminated yet",
			LastTransitionTime: now,
			ObservedGeneration: s.Generation,
		})
	case ok:
		s.Status.ReportLocation = uri
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionReportUploaded,
			Status:             metav1.ConditionTrue,
			Reason:             "ObjectStoreUploadSucceeded",
			Message:            uri,
			LastTransitionTime: now,
			ObservedGeneration: s.Generation,
		})
	default:
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionReportUploaded,
			Status:             metav1.ConditionFalse,
			Reason:             "ObjectStoreUploadFailed",
			Message:            uri,
			LastTransitionTime: now,
			ObservedGeneration: s.Generation,
		})
	}
}