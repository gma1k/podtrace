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
func ValidateSessionTemplateMetadata(meta PodTraceSessionTemplateMetadata) error {
	base := field.NewPath("spec", "sessionTemplate", "metadata")
	var errs field.ErrorList
	errs = append(errs, metav1validation.ValidateLabels(meta.Labels, base.Child("labels"))...)
	errs = append(errs, apivalidation.ValidateAnnotations(meta.Annotations, base.Child("annotations"))...)
	return errs.ToAggregate()
}
