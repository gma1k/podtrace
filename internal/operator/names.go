package operator

import (
	"fmt"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func validateManagedCRName(kind, name string) error {
	if len(name) > podtracev1alpha1.MaxManagedCRNameLength {
		return fmt.Errorf(
			"metadata.name is %d characters; %s names are limited to %d because the name is stamped into a Kubernetes label value, which is capped at %d characters",
			len(name), kind, podtracev1alpha1.MaxManagedCRNameLength, podtracev1alpha1.MaxManagedCRNameLength)
	}
	return nil
}
