package operator

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func captureEnv(c *podtracev1alpha1.CaptureSpec) []corev1.EnvVar {
	if c == nil || len(c.Headers) == 0 {
		return nil
	}
	return []corev1.EnvVar{{
		Name:  "PODTRACE_CAPTURE_HEADERS",
		Value: strings.Join(c.Headers, ","),
	}}
}
