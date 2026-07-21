package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

func saveRunPodtraceGlobals(t *testing.T) {
	t.Helper()
	orig := struct {
		namespace          string
		containerName      string
		eventFilter        string
		exportFormat       string
		errorRateThreshold float64
		rttSpikeThreshold  float64
		fsSlowThreshold    float64
		showVersion        bool
		watchAppName       string
		watchLabels        []string
		podSelector        string
		podsCSV            string
		namespacesCSV      string
		allInNamespace     bool
		exporterFromFile   string
		preresolvedPods    []string
		diagnoseDuration   string
		enableMetrics      bool
		enableTracing      bool
		enableProfiling    bool
		resolverFactory    func() (kubernetes.PodResolverInterface, error)
		tracerFactory      func() (ebpf.TracerInterface, error)
	}{
		namespace, containerName, eventFilter, exportFormat,
		errorRateThreshold, rttSpikeThreshold, fsSlowThreshold, showVersion,
		watchAppName, watchLabels, podSelector, podsCSV, namespacesCSV,
		allInNamespace, exporterFromFile, preresolvedPods, diagnoseDuration,
		enableMetrics, enableTracing, enableProfiling, resolverFactory, tracerFactory,
	}
	t.Cleanup(func() {
		namespace = orig.namespace
		containerName = orig.containerName
		eventFilter = orig.eventFilter
		exportFormat = orig.exportFormat
		errorRateThreshold = orig.errorRateThreshold
		rttSpikeThreshold = orig.rttSpikeThreshold
		fsSlowThreshold = orig.fsSlowThreshold
		showVersion = orig.showVersion
		watchAppName = orig.watchAppName
		watchLabels = orig.watchLabels
		podSelector = orig.podSelector
		podsCSV = orig.podsCSV
		namespacesCSV = orig.namespacesCSV
		allInNamespace = orig.allInNamespace
		exporterFromFile = orig.exporterFromFile
		preresolvedPods = orig.preresolvedPods
		diagnoseDuration = orig.diagnoseDuration
		enableMetrics = orig.enableMetrics
		enableTracing = orig.enableTracing
		enableProfiling = orig.enableProfiling
		resolverFactory = orig.resolverFactory
		tracerFactory = orig.tracerFactory
	})
}

func resetRunPodtraceGlobals() {
	namespace = "default"
	containerName = ""
	eventFilter = ""
	exportFormat = ""
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	showVersion = false
	watchAppName = ""
	watchLabels = nil
	podSelector = ""
	podsCSV = ""
	namespacesCSV = ""
	allInNamespace = false
	exporterFromFile = ""
	preresolvedPods = nil
	diagnoseDuration = ""
	enableMetrics = false
	enableTracing = false
	enableProfiling = false
}

func cmdWithNamespaceChanged() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("namespace", "default", "")
	_ = cmd.Flags().Set("namespace", "default")
	return cmd
}

func TestRunPodtrace_ShowVersionReturnsNil(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	showVersion = true

	if err := runPodtrace(&cobra.Command{}, nil); err != nil {
		t.Fatalf("showVersion should return nil, got %v", err)
	}
}

func TestRunPodtrace_AppAndLabelMutuallyExclusive(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	watchAppName = "checkout"
	watchLabels = []string{"app=api"}

	err := runPodtrace(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "--app and --label are mutually exclusive") {
		t.Fatalf("expected app/label mutual-exclusion error, got %v", err)
	}
}

func TestRunPodtrace_AppLabelAndPodSelectorMutuallyExclusive(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	watchAppName = "checkout"
	podSelector = "app=api"

	err := runPodtrace(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "--app/--label and --pod-selector are mutually exclusive") {
		t.Fatalf("expected app/label vs pod-selector error, got %v", err)
	}
}

func TestRunPodtrace_MultipleLabelsRejected(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	watchLabels = []string{"a=b", "c=d"}

	err := runPodtrace(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "target an application") {
		t.Fatalf("expected multiple-label error pointing at an application, got %v", err)
	}
}

func TestRunPodtrace_AppSetsPodSelector(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	watchAppName = "checkout"
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return nil, errors.New("stop before cluster")
	}

	err := runPodtrace(cmdWithNamespaceChanged(), nil)
	if err == nil || !strings.Contains(err.Error(), "failed to create pod resolver") {
		t.Fatalf("expected resolver-factory error, got %v", err)
	}
	if want := appNameLabel + "=checkout"; podSelector != want {
		t.Fatalf("--app should set podSelector to %q, got %q", want, podSelector)
	}
}

func TestRunPodtrace_SingleLabelSetsPodSelector(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	watchLabels = []string{"app=api"}
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return nil, errors.New("stop before cluster")
	}

	err := runPodtrace(cmdWithNamespaceChanged(), nil)
	if err == nil || !strings.Contains(err.Error(), "failed to create pod resolver") {
		t.Fatalf("expected resolver-factory error, got %v", err)
	}
	if podSelector != "app=api" {
		t.Fatalf("single --label should set podSelector to %q, got %q", "app=api", podSelector)
	}
}

func TestRunPodtrace_ExporterFromFileLoadError(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	exporterFromFile = filepath.Join(t.TempDir(), "does-not-exist.yaml")

	err := runPodtrace(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "load --exporter-from-file") {
		t.Fatalf("expected exporter-from-file load error, got %v", err)
	}
}

func TestRunPodtrace_InvalidPodsEntryNamespace(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	podsCSV = "Bad_NS/mypod"

	err := runPodtrace(cmdWithNamespaceChanged(), nil)
	if err == nil || !strings.Contains(err.Error(), "invalid namespace in --pods entry") {
		t.Fatalf("expected invalid --pods namespace error, got %v", err)
	}
}

func TestRunPodtrace_InvalidPodsEntryPodName(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	podsCSV = "goodns/Bad_Pod!"

	err := runPodtrace(cmdWithNamespaceChanged(), nil)
	if err == nil || !strings.Contains(err.Error(), "invalid pod name in --pods entry") {
		t.Fatalf("expected invalid --pods pod-name error, got %v", err)
	}
}

func TestRunPodtrace_NoTargetSelection(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()

	err := runPodtrace(cmdWithNamespaceChanged(), nil)
	if err == nil || !strings.Contains(err.Error(), "target pod selection is required") {
		t.Fatalf("expected target-selection-required error, got %v", err)
	}
}
