package operator

import (
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// Environment variable names the agent reads for the continuous metrics
// plane. Kept together so the mapping from CRD field to env var is
// readable in one place.
const (
	envMetricsEnabled           = "PODTRACE_WORKLOAD_METRICS"
	envMetricsExcludeNamespaces = "PODTRACE_WORKLOAD_METRICS_EXCLUDE_NAMESPACES"
	envMetricsSeriesBudget      = "PODTRACE_WORKLOAD_METRICS_SERIES_BUDGET"
	envMetricsNativeHistograms  = "PODTRACE_WORKLOAD_METRICS_NATIVE_HISTOGRAMS"
	envMetricsPodLabel          = "PODTRACE_WORKLOAD_METRICS_POD_LABEL"
	envMetricsProcessLabel      = "PODTRACE_WORKLOAD_METRICS_PROCESS_LABEL"
)

// metricsEnv renders AgentMetricsSpec onto the agent container's
// environment.
func metricsEnv(spec *podtracev1alpha1.AgentMetricsSpec) []corev1.EnvVar {
	if spec == nil || !spec.Enabled {
		return nil
	}

	env := []corev1.EnvVar{{Name: envMetricsEnabled, Value: "true"}}

	if namespaces := sanitizeExcludedNamespaces(spec.ExcludeNamespaces); len(namespaces) > 0 {
		env = append(env, corev1.EnvVar{
			Name:  envMetricsExcludeNamespaces,
			Value: strings.Join(namespaces, ","),
		})
	}
	if spec.SeriesBudget != nil {
		env = append(env, corev1.EnvVar{
			Name:  envMetricsSeriesBudget,
			Value: strconv.FormatInt(int64(*spec.SeriesBudget), 10),
		})
	}
	if spec.NativeHistograms != nil {
		env = append(env, corev1.EnvVar{
			Name:  envMetricsNativeHistograms,
			Value: strconv.FormatBool(*spec.NativeHistograms),
		})
	}
	if labels := spec.Labels; labels != nil {
		if labels.Pod {
			env = append(env, corev1.EnvVar{Name: envMetricsPodLabel, Value: "true"})
		}
		if labels.Process {
			env = append(env, corev1.EnvVar{Name: envMetricsProcessLabel, Value: "true"})
		}
	}
	return env
}

// sanitizeExcludedNamespaces drops blanks and duplicates and returns the
// result in the order given.
func sanitizeExcludedNamespaces(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, name := range in {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, ",= \t\n") {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}
