package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/logger"
	"go.uber.org/zap"
)

func finalizeDiagnoseOutputs(ctx context.Context, report string, d *diagnose.Diagnostician) {
	if summaryFile == "" && terminationMessagePath == "" && reportTo == "" {
		return
	}
	node := os.Getenv("NODE_NAME")
	summary := computeSessionSummary(d, node)
	if err := emitSessionArtifacts(ctx, summary, report); err != nil {
		logger.Warn("emit session artifacts", zap.Error(err))
	}
}

// SessionSummary is the compact, machine-readable summary the CLI emits
// at the end of --diagnose. Matches the CRD's SessionSummary type
// field-for-field so the operator can JSON-unmarshal the termination
// message directly.
type SessionSummary struct {
	TotalEvents    int64  `json:"totalEvents"`
	DNSEvents      int64  `json:"dnsEvents,omitempty"`
	NetEvents      int64  `json:"netEvents,omitempty"`
	FSEvents       int64  `json:"fsEvents,omitempty"`
	CPUEvents      int64  `json:"cpuEvents,omitempty"`
	ProcEvents     int64  `json:"procEvents,omitempty"`
	ErrorsDetected int32  `json:"errorsDetected,omitempty"`
	DurationMS     int64  `json:"durationMs,omitempty"`
	Node           string `json:"node,omitempty"`
}

// computeSessionSummary rolls up a Diagnostician's observed events into
// the small struct Kubernetes surfaces in pod status.
func computeSessionSummary(d *diagnose.Diagnostician, node string) SessionSummary {
	events := d.GetEvents()
	summary := SessionSummary{
		TotalEvents: int64(len(events)),
		DurationMS:  d.EndTime().Sub(d.StartTime()).Milliseconds(),
		Node:        node,
	}
	for _, ev := range events {
		if ev == nil {
			continue
		}
		switch categoryForEventType(ev.TypeString()) {
		case "dns":
			summary.DNSEvents++
		case "net":
			summary.NetEvents++
		case "fs":
			summary.FSEvents++
		case "cpu":
			summary.CPUEvents++
		case "proc":
			summary.ProcEvents++
		}
		if ev.Error != 0 {
			summary.ErrorsDetected++
		}
	}
	return summary
}

// categoryForEventType maps the internal events.Event.TypeString() value
// (uppercase category names like DNS/NET/FS/CPU/PROC) into the five
// top-level buckets the PodTrace CRD exposes. Categories outside this
// set (MEM, LOCK, HTTP, …) contribute to TotalEvents but not to any
// per-category count.
func categoryForEventType(typeStr string) string {
	switch strings.ToLower(typeStr) {
	case "dns":
		return "dns"
	case "net":
		return "net"
	case "fs":
		return "fs"
	case "cpu":
		return "cpu"
	case "proc":
		return "proc"
	}
	return ""
}

// emitSessionArtifacts writes the three session artifacts that the
// operator expects when a diagnose session completes:
//
//   - summaryFile: full-fat JSON including per-category breakdown.
//   - terminationMessagePath: compact JSON (<=4KB) surfaced in pod status
//     via Kubernetes' terminationMessagePath contract.
//   - reportTo: patches a ConfigMap or Secret with the human-readable
//     report text (the "full artifact" per spec.reportRef).
//
// All three are best-effort individually: a failure on one does not
// block the others. The return error is a composite when multiple paths
// fail, so the Job log shows the complete picture.
func emitSessionArtifacts(ctx context.Context, summary SessionSummary, reportText string) error {
	var errs []string

	if summaryFile != "" {
		if err := writeSummaryFile(summaryFile, summary); err != nil {
			errs = append(errs, fmt.Sprintf("summary-file: %v", err))
		}
	}
	if terminationMessagePath != "" {
		if err := writeTerminationMessage(terminationMessagePath, summary); err != nil {
			errs = append(errs, fmt.Sprintf("termination-message: %v", err))
		}
	}
	if reportTo != "" {
		if err := uploadReport(ctx, reportTo, reportText); err != nil {
			errs = append(errs, fmt.Sprintf("report-to: %v", err))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("session artifact emission: %s", strings.Join(errs, "; "))
}

// writeSummaryFile writes the JSON summary to the given path. Used by
// the sidecar uploader (reads this file) as the source of truth for
// summary content when the CLI succeeds.
func writeSummaryFile(path string, summary SessionSummary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600) // #nosec G306,G703 -- path is an operator-supplied flag; 0600 is correct for a summary file consumed inside the pod.
}

// writeTerminationMessage writes a compact JSON encoding of the summary
// so the apiserver surfaces it in Pod.Status.ContainerStatuses[].
// State.Terminated.Message. 4KB is the kernel-enforced ceiling on this
// path; the SessionSummary shape intentionally fits well within it.
func writeTerminationMessage(path string, summary SessionSummary) error {
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	const maxTerminationBytes = 4096
	if len(data) > maxTerminationBytes {
		return fmt.Errorf("summary JSON %d bytes exceeds 4KB termination message limit", len(data))
	}
	return os.WriteFile(path, data, 0o600) // #nosec G306,G703 -- path is an operator-supplied flag; kubelet reads this via the container runtime, 0600 is appropriate.
}

// uploadReport parses a report-to spec of the form "kind/namespace/name"
// and patches the named ConfigMap or Secret with the report text. Uses
// the in-cluster ServiceAccount; expected to be a narrow Role granting
// patch on exactly this one object.
func uploadReport(ctx context.Context, spec, reportText string) error {
	kind, namespace, name, err := parseReportToSpec(spec)
	if err != nil {
		return err
	}

	client, err := buildInClusterClient()
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}

	writeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	switch kind {
	case "configmap":
		return upsertReportConfigMap(writeCtx, client, namespace, name, reportText)
	case "secret":
		return upsertReportSecret(writeCtx, client, namespace, name, reportText)
	default:
		return fmt.Errorf("unsupported report-to kind %q (want configmap|secret)", kind)
	}
}

// parseReportToSpec breaks a string of the form "kind/namespace/name"
// into its three components. Case-folds the kind so "ConfigMap",
// "configmap", and "CONFIGMAP" all work.
func parseReportToSpec(spec string) (kind, namespace, name string, err error) {
	parts := strings.Split(spec, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("report-to must be kind/namespace/name, got %q", spec)
	}
	for i, p := range parts {
		if strings.TrimSpace(p) == "" {
			return "", "", "", fmt.Errorf("report-to part %d is empty: %q", i, spec)
		}
	}
	return strings.ToLower(parts[0]), parts[1], parts[2], nil
}

// upsertReportConfigMap creates or updates a ConfigMap with the report
// under the deterministic data key "report.txt". Idempotent: repeated
// invocations overwrite. A separate key holds the summary JSON so the
// final artifact is self-describing.
func upsertReportConfigMap(ctx context.Context, client kubernetes.Interface, namespace, name, reportText string) error {
	data := map[string]string{"report.txt": reportText}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			"podtrace.io/managed-by": "podtrace-cli",
			"podtrace.io/kind":       "session-report",
		}},
		Data: data,
	}
	_, err := client.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create ConfigMap: %w", err)
	}
	existing, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get existing ConfigMap: %w", err)
	}
	if existing.Data == nil {
		existing.Data = map[string]string{}
	}
	existing.Data["report.txt"] = reportText
	if _, err := client.CoreV1().ConfigMaps(namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update ConfigMap: %w", err)
	}
	return nil
}

// upsertReportSecret mirrors upsertReportConfigMap for Secret sinks.
// Secret is the right sink when the report may contain sensitive
// hostnames, paths, or payloads — Kubernetes RBAC on Secrets is
// typically stricter.
func upsertReportSecret(ctx context.Context, client kubernetes.Interface, namespace, name, reportText string) error {
	data := map[string][]byte{"report.txt": []byte(reportText)}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			"podtrace.io/managed-by": "podtrace-cli",
			"podtrace.io/kind":       "session-report",
		}},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	_, err := client.CoreV1().Secrets(namespace).Create(ctx, sec, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create Secret: %w", err)
	}
	existing, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get existing Secret: %w", err)
	}
	if existing.Data == nil {
		existing.Data = map[string][]byte{}
	}
	existing.Data["report.txt"] = []byte(reportText)
	if _, err := client.CoreV1().Secrets(namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update Secret: %w", err)
	}
	return nil
}

// buildInClusterClient constructs a kubernetes.Interface from the Job
// pod's ServiceAccount. Falls back to KUBECONFIG for local development
// so the same code path works when running the CLI outside a cluster
// (e.g., in unit tests) — the fallback is gated on the in-cluster probe
// failing, so production behavior is unchanged.
func buildInClusterClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			return nil, fmt.Errorf("in-cluster config: %w", err)
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
	}
	return kubernetes.NewForConfig(cfg)
}
