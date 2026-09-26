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
	envMetricsSemanticConv      = "PODTRACE_WORKLOAD_METRICS_SEMANTIC_CONVENTIONS"
	envMetricsKernelAggregation = "PODTRACE_WORKLOAD_METRICS_KERNEL_AGGREGATION"
	envMetricsAttributeLimit    = "PODTRACE_WORKLOAD_METRICS_ATTRIBUTE_CARDINALITY"

	envInspectionsEnabled    = "PODTRACE_INSPECTIONS"
	envInspectionsInterval   = "PODTRACE_INSPECTIONS_INTERVAL"
	envInspectionsAlerts     = "PODTRACE_INSPECTIONS_ALERTS"
	envInspectionsBudget     = "PODTRACE_INSPECTIONS_BUDGET"
	envInspectionErrorRate   = "PODTRACE_INSPECTIONS_ERROR_RATE_PCT"
	envInspectionMinRequests = "PODTRACE_INSPECTIONS_MIN_REQUEST_RATE"
	envInspectionMeanLatency = "PODTRACE_INSPECTIONS_MEAN_LATENCY"
	envInspectionsHoldTime   = "PODTRACE_INSPECTIONS_HOLD_TIME"
	envInspectionAcquireMean = "PODTRACE_INSPECTIONS_ACQUIRE_MEAN"
	envInspectionCPUBlocked  = "PODTRACE_INSPECTIONS_CPU_BLOCKED_MEAN"
	envInspectionPoolWarn    = "PODTRACE_INSPECTIONS_POOL_UTILIZATION_PCT"
)

// boolEnv renders a resolved toggle.
func boolEnv(name string, value bool) corev1.EnvVar {
	return corev1.EnvVar{Name: name, Value: strconv.FormatBool(value)}
}

// metricsEnv renders AgentMetricsSpec onto the agent container's
// environment.
func metricsEnv(spec *podtracev1alpha1.AgentMetricsSpec) []corev1.EnvVar {
	if !spec.MetricsEnabled() {
		return []corev1.EnvVar{boolEnv(envMetricsEnabled, false)}
	}

	env := []corev1.EnvVar{
		boolEnv(envMetricsEnabled, true),
		boolEnv(envMetricsNativeHistograms, spec.NativeHistogramsEnabled()),
		boolEnv(envMetricsKernelAggregation, spec.KernelAggregationEnabled()),
	}
	if spec == nil {
		return append(env, inspectionsEnv(nil)...)
	}

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
	if spec.SemanticConventions {
		env = append(env, corev1.EnvVar{Name: envMetricsSemanticConv, Value: "true"})
	}
	if spec.AttributeCardinality != nil {
		env = append(env, corev1.EnvVar{
			Name:  envMetricsAttributeLimit,
			Value: strconv.FormatInt(int64(*spec.AttributeCardinality), 10),
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
	return append(env, inspectionsEnv(spec.Inspections)...)
}

// inspectionsEnv renders AgentInspectionsSpec onto the agent container's
// environment.
func inspectionsEnv(spec *podtracev1alpha1.AgentInspectionsSpec) []corev1.EnvVar {
	if !spec.IsEnabled() {
		return []corev1.EnvVar{boolEnv(envInspectionsEnabled, false)}
	}

	env := []corev1.EnvVar{
		boolEnv(envInspectionsEnabled, true),
		boolEnv(envInspectionsAlerts, spec.RaiseAlerts()),
	}
	if spec == nil {
		return env
	}

	if spec.Interval != nil && spec.Interval.Duration > 0 {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionsInterval,
			Value: spec.Interval.Duration.String(),
		})
	}
	if spec.Budget != nil {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionsBudget,
			Value: strconv.FormatInt(int64(*spec.Budget), 10),
		})
	}

	if spec.HoldTime != nil && spec.HoldTime.Duration > 0 {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionsHoldTime,
			Value: spec.HoldTime.Duration.String(),
		})
	}

	t := spec.Thresholds
	if t == nil {
		return env
	}
	if t.ErrorRatePercent != nil {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionErrorRate,
			Value: strconv.FormatInt(int64(*t.ErrorRatePercent), 10),
		})
	}
	if t.MinRequestsPerMinute != nil {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionMinRequests,
			Value: perMinuteAsPerSecond(*t.MinRequestsPerMinute),
		})
	}
	if t.MeanLatency != nil && t.MeanLatency.Duration > 0 {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionMeanLatency,
			Value: t.MeanLatency.Duration.String(),
		})
	}
	if t.AcquireMean != nil && t.AcquireMean.Duration > 0 {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionAcquireMean,
			Value: t.AcquireMean.Duration.String(),
		})
	}
	if t.CPUBlockedMean != nil {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionCPUBlocked,
			Value: t.CPUBlockedMean.Duration.String(),
		})
	}
	if t.PoolUtilizationPercent != nil {
		env = append(env, corev1.EnvVar{
			Name:  envInspectionPoolWarn,
			Value: strconv.FormatInt(int64(*t.PoolUtilizationPercent), 10),
		})
	}
	return env
}

// perMinuteAsPerSecond renders a per-minute count as a per-second rate.
func perMinuteAsPerSecond(perMinute int32) string {
	return strconv.FormatFloat(float64(perMinute)/60, 'g', -1, 64)
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
