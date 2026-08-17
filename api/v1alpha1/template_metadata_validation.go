package v1alpha1

import (
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateSessionTemplateMetadata rejects labels or annotations a schedule's
// SessionTemplate would stamp onto every child PodTraceSession that the
// apiserver would itself reject (an over-long key, an invalid value, an
// oversized annotation set).
//
// Left unchecked, a bad entry surfaces only when a child create fails, and
// because that create is retried every reconcile the schedule requeues on the
// same error forever. Validated up front in the webhook (and terminally in the
// controller for schedules that predate it) the fault is reported once and the
// schedule stops churning.
func ValidateSessionTemplateMetadata(meta PodTraceSessionTemplateMetadata) error {
	base := field.NewPath("spec", "sessionTemplate", "metadata")
	var errs field.ErrorList
	errs = append(errs, metav1validation.ValidateLabels(meta.Labels, base.Child("labels"))...)
	errs = append(errs, apivalidation.ValidateAnnotations(meta.Annotations, base.Child("annotations"))...)
	return errs.ToAggregate()
}
