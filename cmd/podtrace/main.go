package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"strconv"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/ebpf"
	tracerpkg "github.com/podtrace/podtrace/internal/ebpf/tracer"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/profiling"
	"github.com/podtrace/podtrace/internal/system"
	"github.com/podtrace/podtrace/internal/tracing"
	"github.com/podtrace/podtrace/internal/validation"
)

var (
	namespace             string
	namespacesCSV         string
	podsCSV               string
	podSelector           string
	allInNamespace        bool
	diagnoseDuration      string
	enableMetrics         bool
	enableTracing         bool
	exportFormat          string
	eventFilter           string
	containerName         string
	errorRateThreshold    float64
	rttSpikeThreshold     float64
	fsSlowThreshold       float64
	logLevel              string
	tracingOTLPEndpoint   string
	tracingJaegerEndpoint string
	tracingSplunkEndpoint string
	tracingSplunkToken    string
	tracingSampleRate     float64
	showVersion           bool
	enableProfiling       bool

	resolverFactory func() (kubernetes.PodResolverInterface, error)
	tracerFactory   func() (ebpf.TracerInterface, error)
	exitFunc        func(int)
)

func init() {
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return kubernetes.NewPodResolver()
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return ebpf.NewTracer()
	}
	exitFunc = os.Exit
}

func main() {
	var rootCmd = &cobra.Command{
		Use:          "./bin/podtrace -n <namespace> <pod-name> --diagnose 10s",
		Short:        "eBPF-based troubleshooting tool for Kubernetes pods",
		Long:         `Podtrace attaches eBPF program to a Kubernetes pod's container and prints high-level, human-readable events that help diagnose application issues.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runPodtrace,
		SilenceUsage: true,
	}

	rootCmd.AddCommand(newDiagnoseEnvCmd())

	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", config.DefaultNamespace, "Kubernetes namespace")
	rootCmd.Flags().StringVar(&namespacesCSV, "namespaces", "", "Comma-separated namespaces for multi-pod tracing (e.g., default,prod)")
	rootCmd.Flags().StringVar(&podsCSV, "pods", "", "Comma-separated pod references to trace (pod or namespace/pod)")
	rootCmd.Flags().StringVar(&podSelector, "pod-selector", "", "Kubernetes label selector for target pods (e.g., app=api,team=payments)")
	rootCmd.Flags().BoolVar(&allInNamespace, "all-in-namespace", false, "Trace all pods in --namespace (or all --namespaces)")
	rootCmd.Flags().StringVar(&diagnoseDuration, "diagnose", "", "Run in diagnose mode for the specified duration (e.g., 10s, 5m)")
	rootCmd.Flags().BoolVar(&enableMetrics, "metrics", false, "Enable Prometheus metrics server")
	rootCmd.Flags().StringVar(&exportFormat, "export", "", "Export format for diagnose report (json, csv)")
	rootCmd.Flags().StringVar(&eventFilter, "filter", "", "Filter events by type (dns,net,fs,cpu)")
	rootCmd.Flags().StringVar(&containerName, "container", "", "Container name to trace (default: first container)")
	rootCmd.Flags().Float64Var(&errorRateThreshold, "error-threshold", config.DefaultErrorRateThreshold, "Error rate threshold percentage for issue detection")
	rootCmd.Flags().Float64Var(&rttSpikeThreshold, "rtt-threshold", config.DefaultRTTThreshold, "RTT spike threshold in milliseconds")
	rootCmd.Flags().Float64Var(&fsSlowThreshold, "fs-threshold", config.DefaultFSSlowThreshold, "File system slow operation threshold in milliseconds")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "", "Set log level (debug, info, warn, error, fatal). Overrides PODTRACE_LOG_LEVEL environment variable")
	rootCmd.Flags().BoolVar(&enableTracing, "tracing", config.DefaultTracingEnabled, "Enable distributed tracing")
	rootCmd.Flags().StringVar(&tracingOTLPEndpoint, "tracing-otlp-endpoint", config.DefaultOTLPEndpoint, "OpenTelemetry OTLP endpoint")
	rootCmd.Flags().StringVar(&tracingJaegerEndpoint, "tracing-jaeger-endpoint", config.DefaultJaegerEndpoint, "Jaeger endpoint")
	rootCmd.Flags().StringVar(&tracingSplunkEndpoint, "tracing-splunk-endpoint", config.DefaultSplunkEndpoint, "Splunk HEC endpoint")
	rootCmd.Flags().StringVar(&tracingSplunkToken, "tracing-splunk-token", "", "Splunk HEC token")
	rootCmd.Flags().Float64Var(&tracingSampleRate, "tracing-sample-rate", config.DefaultTracingSampleRate, "Tracing sample rate (0.0-1.0)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Print version information")
	rootCmd.Flags().BoolVar(&enableProfiling, "profiling", false, "Enable performance profiling: pprof endpoint discovery on the target pod, auto-trigger on latency spikes, and CPU/memory correlation in reports")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if logLevel != "" {
			logger.SetLevel(logLevel)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Command execution failed", zap.Error(err))
		exitFunc(1)
	}
	defer logger.Sync()
}

func runPodtrace(cmd *cobra.Command, args []string) error {
	if showVersion {
		fmt.Println(config.GetVersion())
		return nil
	}

	if enableTracing {
		config.TracingEnabled = true
		if tracingOTLPEndpoint != "" {
			config.OTLPEndpoint = tracingOTLPEndpoint
		}
		if tracingJaegerEndpoint != "" {
			config.JaegerEndpoint = tracingJaegerEndpoint
		}
		if tracingSplunkEndpoint != "" {
			config.SplunkEndpoint = tracingSplunkEndpoint
		}
		if tracingSplunkToken != "" {
			config.SplunkToken = tracingSplunkToken
		}
		if tracingSampleRate >= 0.0 && tracingSampleRate <= 1.0 {
			config.TracingSampleRate = tracingSampleRate
		}
	}

	alertManager, err := alerting.NewManager()
	if err != nil {
		logger.Warn("Failed to create alert manager", zap.Error(err))
	} else if alertManager != nil {
		alerting.SetGlobalManager(alertManager)
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
			defer shutdownCancel()
			_ = alertManager.Shutdown(shutdownCtx)
		}()
	}

	var metricsServer *metricsexporter.Server
	if enableMetrics {
		metricsServer = metricsexporter.StartServer()
		defer metricsServer.Shutdown()
	}

	tracingManager, err := tracing.NewManager()
	if err != nil {
		logger.Warn("Failed to create tracing manager", zap.Error(err))
	} else if tracingManager != nil && enableTracing {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := tracingManager.Start(ctx); err != nil {
			logger.Warn("Failed to start tracing manager", zap.Error(err))
		} else {
			defer func() {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
				defer shutdownCancel()
				_ = tracingManager.Shutdown(shutdownCtx)
			}()
		}
	}

	var argPodName string
	if len(args) > 0 {
		argPodName = strings.TrimSpace(args[0])
		if err := validation.ValidatePodName(argPodName); err != nil {
			return fmt.Errorf("invalid pod name: %w", err)
		}
	}

	if err := validation.ValidateNamespace(namespace); err != nil {
		return fmt.Errorf("invalid namespace: %w", err)
	}
	namespaces := parseCSV(namespacesCSV)
	for _, ns := range namespaces {
		if err := validation.ValidateNamespace(ns); err != nil {
			return fmt.Errorf("invalid namespace in --namespaces: %w", err)
		}
	}
	pods := parseCSV(podsCSV)
	if argPodName != "" {
		pods = append([]string{argPodName}, pods...)
	}
	if len(pods) == 0 && podSelector == "" && !allInNamespace {
		return fmt.Errorf("target pod selection is required: pass <pod-name>, --pods, --pod-selector, or --all-in-namespace")
	}
	for _, p := range pods {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		name := p
		if strings.Contains(p, "/") {
			parts := strings.SplitN(p, "/", 2)
			if err := validation.ValidateNamespace(parts[0]); err != nil {
				return fmt.Errorf("invalid namespace in --pods entry %q: %w", p, err)
			}
			name = parts[1]
		}
		if err := validation.ValidatePodName(name); err != nil {
			return fmt.Errorf("invalid pod name in --pods entry %q: %w", p, err)
		}
	}

	if err := validation.ValidateContainerName(containerName); err != nil {
		return fmt.Errorf("invalid container name: %w", err)
	}

	if err := validation.ValidateExportFormat(exportFormat); err != nil {
		return fmt.Errorf("invalid export format: %w", err)
	}

	if err := validation.ValidateEventFilter(eventFilter); err != nil {
		return fmt.Errorf("invalid event filter: %w", err)
	}

	if err := validation.ValidateErrorRateThreshold(errorRateThreshold); err != nil {
		return fmt.Errorf("invalid error threshold: %w", err)
	}
	if err := validation.ValidateRTTThreshold(rttSpikeThreshold); err != nil {
		return fmt.Errorf("invalid RTT threshold: %w", err)
	}
	if err := validation.ValidateFSThreshold(fsSlowThreshold); err != nil {
		return fmt.Errorf("invalid file system threshold: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	resolver, err := resolverFactory()
	if err != nil {
		return fmt.Errorf("failed to create pod resolver: %w", err)
	}

	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), config.DefaultPodResolveTimeout)
	defer resolveCancel()
	selection := kubernetes.TargetSelection{
		DefaultNamespace: namespace,
		Namespaces:       namespaces,
		PodSelector:      podSelector,
		AllInNamespace:   allInNamespace,
		Pods:             pods,
		ContainerName:    containerName,
	}
	targetInfos := make([]*kubernetes.PodInfo, 0, 8)
	var targetRegistry *kubernetes.TargetRegistry

	_, useDynamicTargets := resolver.(kubernetes.ClientsetProvider)
	useDynamicTargets = useDynamicTargets && (len(selection.Pods) > 1 || selection.PodSelector != "" || selection.AllInNamespace || len(selection.Namespaces) > 1)
	if useDynamicTargets {
		clientset := resolver.(kubernetes.ClientsetProvider).GetClientset()
		targetRegistry = kubernetes.NewTargetRegistry(clientset, selection)
		if err := targetRegistry.Start(ctx); err != nil {
			return fmt.Errorf("failed to start target registry: %w", err)
		}
		targetInfos = targetRegistry.Snapshot()
		if len(targetInfos) == 0 {
			return fmt.Errorf("target selection matched zero running pods")
		}
	} else {
		for _, podRef := range selection.Pods {
			podNs, podName := parsePodRef(podRef, namespace)
			info, err := resolver.ResolvePod(resolveCtx, podName, podNs, containerName)
			if err != nil {
				return fmt.Errorf("failed to resolve pod %s/%s: %w", podNs, podName, err)
			}
			targetInfos = append(targetInfos, info)
		}
	}
	if len(targetInfos) == 0 {
		return fmt.Errorf("target selection resolved zero pods")
	}
	podInfo := targetInfos[0]
	sourceIndex := newSourcePodIndex(targetInfos)

	for _, p := range targetInfos {
		logger.Info("Resolved target pod",
			zap.String("namespace", p.Namespace),
			zap.String("pod", p.PodName),
			zap.String("container_id", p.ContainerID),
			zap.String("cgroup_path", p.CgroupPath))
		if os.Getenv("PODTRACE_ALLOW_BROAD_CGROUP") == "1" || p.CgroupPath == "" {
			continue
		}
		short := p.ContainerID
		if len(short) > 12 {
			short = short[:12]
		}
		if !strings.Contains(p.CgroupPath, p.ContainerID) && (short == "" || !strings.Contains(p.CgroupPath, short)) {
			return fmt.Errorf(
				"resolved cgroup path %q does not contain container id %q; refusing to run.\n\n"+
					"This safety check prevents accidentally tracing the wrong container.\n\n"+
					"Common causes and fixes:\n"+
					"  • OpenShift/OKD: CRI-O may use a cgroup path that omits the container ID.\n"+
					"  • Talos Linux: custom cgroup layout may not embed the container ID.\n"+
					"  • Custom kubelet --cgroup-parent may produce parent-level slice paths.\n\n"+
					"To bypass this check: set PODTRACE_ALLOW_BROAD_CGROUP=1\n"+
					"To inspect the path:  ls /sys/fs/cgroup/**/*%s* 2>/dev/null || true",
				p.CgroupPath, short, short)
		}
	}

	// Check kernel version, BTF availability, and SELinux before loading eBPF.
	if err := system.CheckRequirements(); err != nil {
		return err
	}
	system.CheckSELinux()

	tracer, err := tracerFactory()
	if err != nil {
		return fmt.Errorf("failed to create tracer: %w", err)
	}
	defer func() { _ = tracer.Stop() }()

	cgroupPaths := make([]string, 0, len(targetInfos))
	containerIDs := make([]string, 0, len(targetInfos))
	for _, target := range targetInfos {
		cgroupPaths = append(cgroupPaths, target.CgroupPath)
		containerIDs = append(containerIDs, target.ContainerID)
	}
	if err := attachTracerToCgroups(tracer, cgroupPaths); err != nil {
		return fmt.Errorf("failed to attach to cgroups: %w", err)
	}
	if err := setTracerContainerIDs(tracer, containerIDs); err != nil {
		return fmt.Errorf("failed to set container IDs: %w", err)
	}
	if targetRegistry != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case snapshot := <-targetRegistry.Updates():
					if len(snapshot) == 0 {
						logger.Warn("Target registry currently empty; retaining previous cgroup filters")
						continue
					}
					nextCgroups := make([]string, 0, len(snapshot))
					for _, s := range snapshot {
						nextCgroups = append(nextCgroups, s.CgroupPath)
					}
					if err := attachTracerToCgroups(tracer, nextCgroups); err != nil {
						logger.Warn("Failed to apply dynamic cgroup target update", zap.Error(err))
						continue
					}
					sourceIndex.Replace(snapshot)
					logger.Info("Updated dynamic target set", zap.Int("pods", len(snapshot)))
				}
			}
		}()
	}

	var enricher *kubernetes.ContextEnricher
	var eventsCorrelator *kubernetes.EventsCorrelator
	enrichmentEnabled := os.Getenv("PODTRACE_K8S_ENRICHMENT_ENABLED") != "false"
	if enrichmentEnabled {
		if clientsetProvider, ok := resolver.(kubernetes.ClientsetProvider); ok {
			clientset := clientsetProvider.GetClientset()
			if clientset != nil {
				enricher = kubernetes.NewContextEnricher(clientset, podInfo)
				enricher.Start(ctx)
				defer enricher.Stop()
				eventsCorrelator = kubernetes.NewEventsCorrelator(clientset, podInfo.PodName, podInfo.Namespace)
				if err := eventsCorrelator.Start(ctx); err != nil {
					logger.Warn("Failed to start Kubernetes events correlator", zap.Error(err))
				} else {
					defer eventsCorrelator.Stop()
				}
			}
		}
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	if enableMetrics {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Panic in metrics event handler",
						zap.Any("panic", r),
						zap.ByteString("stack", debug.Stack()))
				}
			}()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-eventChan:
					if !ok {
						return
					}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, event)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx := buildK8sContextMap(enriched, sourceIndex.Resolve(event))
							metricsexporter.HandleEventWithContext(event, k8sCtx)
						} else {
							metricsexporter.HandleEvent(event)
						}
					} else {
						metricsexporter.HandleEvent(event)
					}
				}
			}
		}()
	}

	if tracingManager != nil && enableTracing {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Panic in tracing event handler",
						zap.Any("panic", r),
						zap.ByteString("stack", debug.Stack()))
				}
			}()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-eventChan:
					if !ok {
						return
					}
					var k8sCtx interface{}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, event)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx = buildK8sContextMap(enriched, sourceIndex.Resolve(event))
						}
					}
					tracingManager.ProcessEvent(event, k8sCtx)
				}
			}
		}()
	}

	// Profiling handler — set up before tracer.Start() so management routes are ready.
	var profilingHandler *profiling.Handler
	if enableProfiling || config.ProfilingEnabled {
		config.ProfilingEnabled = true // ensures MetricsEnablePprof() returns true
		ports := parsePprofPorts(config.ProfilingPprofPorts)
		if podInfo != nil && podInfo.PodIP != "" {
			profilingHandler = profiling.NewHandler(podInfo.PodIP, ports)
			go profilingHandler.Run(ctx, eventChan)
		} else {
			logger.Warn("Profiling requested but pod IP is not available; skipping pprof discovery")
		}
		// Wire profiling routes into the management HTTP server.
		if profilingHandler != nil {
			if setter, ok := tracer.(tracerpkg.ProfilingControllerSetter); ok {
				setter.SetProfilingController(profilingHandler)
			}
		}
	}

	enrichedChan := eventChan

	filteredChan := enrichedChan
	if eventFilter != "" {
		filteredChan = make(chan *events.Event, config.EventChannelBufferSize)
		go filterEvents(ctx, enrichedChan, filteredChan, eventFilter)
	}

	if enableMetrics {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					metricsexporter.RecordChannelDepths(len(eventChan), len(filteredChan))
				}
			}
		}()
	}

	if err := tracer.Start(ctx, eventChan); err != nil {
		return fmt.Errorf("failed to start tracer: %w", err)
	}

	if diagnoseDuration != "" {
		return runDiagnoseModeWithSource(ctx, filteredChan, diagnoseDuration, podInfo, enricher, eventsCorrelator, tracingManager, enableTracing, sourceIndex.Resolve, profilingHandler)
	}

	return runNormalModeWithSource(ctx, filteredChan, podInfo, enricher, eventsCorrelator, tracingManager, enableTracing, sourceIndex.Resolve, profilingHandler)
}

func runNormalMode(ctx context.Context, eventChan <-chan *events.Event, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, eventsCorrelator *kubernetes.EventsCorrelator, tracingManager *tracing.Manager, enableTracing bool) error {
	return runNormalModeWithSource(ctx, eventChan, podInfo, enricher, eventsCorrelator, tracingManager, enableTracing, nil, nil)
}

func runNormalModeWithSource(ctx context.Context, eventChan <-chan *events.Event, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, _ *kubernetes.EventsCorrelator, tracingManager *tracing.Manager, enableTracing bool, resolveSource func(*events.Event) *kubernetes.PodInfo, profilingHandler *profiling.Handler) error {
	logger.Info("Tracing started",
		zap.Duration("update_interval", config.DefaultRealtimeUpdateInterval))

	var diagnostician *diagnose.Diagnostician
	if podInfo != nil && enricher != nil {
		diagnostician = diagnose.NewDiagnosticianWithK8sAndThresholds(podInfo.PodName, podInfo.Namespace, errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	} else {
		diagnostician = diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	}
	ticker := time.NewTicker(config.DefaultRealtimeUpdateInterval)
	defer ticker.Stop()

	hasPrintedReport := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-eventChan:
			var k8sCtx map[string]interface{}
			if enricher != nil {
				enriched := enricher.EnrichEvent(ctx, event)
				if enriched != nil && enriched.KubernetesContext != nil {
					k8sCtx = buildK8sContextMap(enriched, resolveSourcePod(resolveSource, event))
					diagnostician.AddEventWithContext(event, k8sCtx)
				} else {
					diagnostician.AddEvent(event)
				}
			} else {
				diagnostician.AddEvent(event)
			}
			if tracingManager != nil && enableTracing {
				var k8sCtxInterface interface{}
				if k8sCtx != nil {
					k8sCtxInterface = k8sCtx
				}
				tracingManager.ProcessEvent(event, k8sCtxInterface)
			}

		case <-ticker.C:
			diagnostician.Finish()

			if hasPrintedReport {
				fmt.Print("\033[2J\033[H")
			}

			report := diagnostician.GenerateReport()
			fmt.Println("=== Real-time Diagnostic Report (updating every 5s) ===")
			fmt.Println("Press Ctrl+C to stop and see final report.")
			fmt.Println()
			fmt.Println(report)
			hasPrintedReport = true

		case <-ctx.Done():
			diagnostician.Finish()
			if hasPrintedReport {
				fmt.Print("\033[2J\033[H")
			}
			fmt.Println("\n=== Final Diagnostic Report ===")
			fmt.Println()
			finalDuration := diagnostician.EndTime().Sub(diagnostician.StartTime())
			report := diagnostician.GenerateReport()
			if profilingHandler != nil {
				report += profilingHandler.GenerateSection(diagnostician.GetEvents(), finalDuration)
			}
			fmt.Println(report)
			return nil
		}
	}
}

func runDiagnoseMode(ctx context.Context, eventChan <-chan *events.Event, durationStr string, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, eventsCorrelator *kubernetes.EventsCorrelator, tracingManager *tracing.Manager, enableTracing bool) error {
	return runDiagnoseModeWithSource(ctx, eventChan, durationStr, podInfo, enricher, eventsCorrelator, tracingManager, enableTracing, nil, nil)
}

func runDiagnoseModeWithSource(ctx context.Context, eventChan <-chan *events.Event, durationStr string, podInfo *kubernetes.PodInfo, enricher *kubernetes.ContextEnricher, _ *kubernetes.EventsCorrelator, tracingManager *tracing.Manager, enableTracing bool, resolveSource func(*events.Event) *kubernetes.PodInfo, profilingHandler *profiling.Handler) error {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	if err := validation.ValidateDiagnoseDuration(duration); err != nil {
		return err
	}

	logger.Info("Running diagnose mode", zap.Duration("duration", duration))

	var diagnostician *diagnose.Diagnostician
	if podInfo != nil && enricher != nil {
		diagnostician = diagnose.NewDiagnosticianWithK8sAndThresholds(podInfo.PodName, podInfo.Namespace, errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	} else {
		diagnostician = diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	}
	timeout := time.After(duration)
	batchTicker := time.NewTicker(config.BatchProcessingInterval)
	defer batchTicker.Stop()
	eventBatch := make([]*events.Event, 0, config.EventBatchSize)

	for {
		select {
		case <-ctx.Done():
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			if profilingHandler != nil {
				report += profilingHandler.GenerateSection(diagnostician.GetEvents(), duration)
			}
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println(report)
			return ctx.Err()
		case event := <-eventChan:
			eventBatch = append(eventBatch, event)
			if len(eventBatch) >= config.EventBatchSize {
				for _, e := range eventBatch {
					var k8sCtx map[string]interface{}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, e)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx = buildK8sContextMap(enriched, resolveSourcePod(resolveSource, e))
							diagnostician.AddEventWithContext(e, k8sCtx)
						} else {
							diagnostician.AddEvent(e)
						}
					} else {
						diagnostician.AddEvent(e)
					}
					if tracingManager != nil && enableTracing {
						var k8sCtxInterface interface{}
						if k8sCtx != nil {
							k8sCtxInterface = k8sCtx
						}
						tracingManager.ProcessEvent(e, k8sCtxInterface)
					}
				}
				eventBatch = eventBatch[:0]
			}
		case <-batchTicker.C:
			if len(eventBatch) > 0 {
				for _, e := range eventBatch {
					var k8sCtx map[string]interface{}
					if enricher != nil {
						enriched := enricher.EnrichEvent(ctx, e)
						if enriched != nil && enriched.KubernetesContext != nil {
							k8sCtx = buildK8sContextMap(enriched, resolveSourcePod(resolveSource, e))
							diagnostician.AddEventWithContext(e, k8sCtx)
						} else {
							diagnostician.AddEvent(e)
						}
					} else {
						diagnostician.AddEvent(e)
					}
					if tracingManager != nil && enableTracing {
						var k8sCtxInterface interface{}
						if k8sCtx != nil {
							k8sCtxInterface = k8sCtx
						}
						tracingManager.ProcessEvent(e, k8sCtxInterface)
					}
				}
				eventBatch = eventBatch[:0]
			}
		case <-timeout:
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			if profilingHandler != nil {
				report += profilingHandler.GenerateSection(diagnostician.GetEvents(), duration)
			}
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println(report)
			return nil
		case <-ctx.Done():
			diagnostician.Finish()
			report := diagnostician.GenerateReport()
			if profilingHandler != nil {
				report += profilingHandler.GenerateSection(diagnostician.GetEvents(), duration)
			}
			if exportFormat != "" {
				return exportReport(report, exportFormat, diagnostician)
			}
			fmt.Println("\n=== Final Diagnostic Report ===")
			fmt.Println()
			fmt.Println(report)
			return nil
		}
	}
}

func filterEvents(ctx context.Context, in <-chan *events.Event, out chan<- *events.Event, filter string) {
	defer close(out)
	filters := strings.Split(strings.ToLower(filter), ",")
	filterMap := make(map[string]bool, len(filters))
	for _, f := range filters {
		f = strings.TrimSpace(f)
		if f != "" {
			filterMap[f] = true
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-in:
			if !ok {
				return
			}
			if event == nil {
				continue
			}
			shouldInclude := false
			switch {
			case filterMap["dns"] && event.Type == events.EventDNS:
				shouldInclude = true
			case filterMap["net"] && (event.Type == events.EventConnect || event.Type == events.EventTCPSend || event.Type == events.EventTCPRecv):
				shouldInclude = true
			case filterMap["fs"] && (event.Type == events.EventRead || event.Type == events.EventWrite || event.Type == events.EventFsync):
				shouldInclude = true
			case filterMap["cpu"] && event.Type == events.EventSchedSwitch:
				shouldInclude = true
			case filterMap["proc"] && (event.Type == events.EventExec || event.Type == events.EventFork || event.Type == events.EventOpen || event.Type == events.EventClose):
				shouldInclude = true
			}
			if shouldInclude {
				select {
				case <-ctx.Done():
					return
				case out <- event:
				default:
					logger.Warn("Filtered event channel full, dropping event",
						zap.String("event_type", event.TypeString()),
						zap.Uint32("pid", event.PID))
					metricsexporter.RecordRingBufferDrop()
				}
			}
		}
	}
}

func exportReport(_ string, format string, d *diagnose.Diagnostician) error {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "json":
		data := d.ExportJSON()
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	case "csv":
		return d.ExportCSV(os.Stdout)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

type sourcePodIndex struct {
	mu    sync.RWMutex
	byCG  map[uint64]*kubernetes.PodInfo
	byNSP map[string]*kubernetes.PodInfo
}

func newSourcePodIndex(targets []*kubernetes.PodInfo) *sourcePodIndex {
	s := &sourcePodIndex{
		byCG:  make(map[uint64]*kubernetes.PodInfo),
		byNSP: make(map[string]*kubernetes.PodInfo),
	}
	s.Replace(targets)
	return s
}

func (s *sourcePodIndex) Replace(targets []*kubernetes.PodInfo) {
	nextByCG := make(map[uint64]*kubernetes.PodInfo, len(targets))
	nextByNSP := make(map[string]*kubernetes.PodInfo, len(targets))
	for _, t := range targets {
		if t == nil {
			continue
		}
		cp := *t
		nextByNSP[t.Namespace+"/"+t.PodName] = &cp
		if cgid, err := cgroupIDFromPath(t.CgroupPath); err == nil && cgid != 0 {
			nextByCG[cgid] = &cp
		}
	}
	s.mu.Lock()
	s.byCG = nextByCG
	s.byNSP = nextByNSP
	s.mu.Unlock()
}

func (s *sourcePodIndex) Resolve(event *events.Event) *kubernetes.PodInfo {
	if s == nil || event == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.byCG[event.CgroupID]; ok {
		return p
	}
	return nil
}

func cgroupIDFromPath(path string) (uint64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0, fmt.Errorf("unsupported stat type for cgroup path")
	}
	return sys.Ino, nil
}

func attachTracerToCgroups(tr ebpf.TracerInterface, cgroupPaths []string) error {
	if multi, ok := tr.(interface {
		AttachToCgroups(cgroupPaths []string) error
	}); ok {
		return multi.AttachToCgroups(cgroupPaths)
	}
	if len(cgroupPaths) == 0 {
		return fmt.Errorf("no cgroup paths provided")
	}
	return tr.AttachToCgroup(cgroupPaths[0])
}

func setTracerContainerIDs(tr ebpf.TracerInterface, containerIDs []string) error {
	if multi, ok := tr.(interface {
		SetContainerIDs(containerIDs []string) error
	}); ok {
		return multi.SetContainerIDs(containerIDs)
	}
	if len(containerIDs) == 0 {
		return fmt.Errorf("no container IDs provided")
	}
	return tr.SetContainerID(containerIDs[0])
}

func resolveSourcePod(resolve func(*events.Event) *kubernetes.PodInfo, e *events.Event) *kubernetes.PodInfo {
	if resolve == nil {
		return nil
	}
	return resolve(e)
}

func buildK8sContextMap(enriched *kubernetes.EnrichedEvent, source *kubernetes.PodInfo) map[string]interface{} {
	if enriched == nil || enriched.KubernetesContext == nil {
		return nil
	}
	ctx := map[string]interface{}{
		"namespace":         enriched.KubernetesContext.SourceNamespace,
		"target_pod":        enriched.KubernetesContext.TargetPodName,
		"target_service":    enriched.KubernetesContext.ServiceName,
		"target_namespace":  enriched.KubernetesContext.TargetNamespace,
		"target_labels":     enriched.KubernetesContext.TargetLabels,
		"service_namespace": enriched.KubernetesContext.ServiceNamespace,
		"is_external":       enriched.KubernetesContext.IsExternal,
	}
	if source != nil {
		ctx["source_pod"] = source.PodName
		ctx["source_namespace"] = source.Namespace
		ctx["source_labels"] = source.Labels
		ctx["source_workload_kind"] = source.OwnerKind
		ctx["source_workload_name"] = source.OwnerName
	}
	if enriched.KubernetesContext.TargetLabels != nil {
		if v := detectServiceMesh(enriched.KubernetesContext.TargetLabels); v != "" {
			ctx["target_mesh"] = v
		}
	}
	if source != nil && source.Labels != nil {
		if v := detectServiceMesh(source.Labels); v != "" {
			ctx["source_mesh"] = v
		}
	}
	return ctx
}

func detectServiceMesh(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	if _, ok := labels["sidecar.istio.io/status"]; ok {
		return "istio"
	}
	if _, ok := labels["istio.io/rev"]; ok {
		return "istio"
	}
	if _, ok := labels["linkerd.io/proxy-version"]; ok {
		return "linkerd"
	}
	if _, ok := labels["kuma.io/sidecar-injected"]; ok {
		return "kuma"
	}
	return ""
}

func parseCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// parsePprofPorts parses a comma-separated list of port numbers from a config
// string (e.g. "6060,8080,9090") and returns valid port integers.
func parsePprofPorts(csv string) []int {
	parts := parseCSV(csv)
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 && n <= 65535 {
			ports = append(ports, n)
		}
	}
	if len(ports) == 0 {
		return []int{6060, 8080, 8081, 9090, 2345}
	}
	return ports
}

func parsePodRef(podRef, defaultNamespace string) (namespace, podName string) {
	podRef = strings.TrimSpace(podRef)
	if strings.Contains(podRef, "/") {
		parts := strings.SplitN(podRef, "/", 2)
		return parts[0], parts[1]
	}
	return defaultNamespace, podRef
}

func interruptChan() <-chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	return sigChan
}
