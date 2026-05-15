package operator

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
)

// registerReconcilers wires every reconciler onto the manager. Order
// does not matter — the manager starts them in parallel — but we
// construct them in dependency order (TracerConfig first, then
// Session, then PodTrace, then ExporterConfig) so a stack trace
// points at the failing one.
func registerReconcilers(mgr ctrl.Manager, opts Options) error {
	if err := registerExporterConfigIndexers(context.Background(), mgr); err != nil {
		return fmt.Errorf("ExporterConfig indexers: %w", err)
	}

	tcr := &TracerConfigReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		SystemNamespace: opts.SystemNamespace,
	}
	if err := tcr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("TracerConfigReconciler: %w", err)
	}

	ptsr := &PodTraceSessionReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		SystemNamespace: opts.SystemNamespace,
	}
	if err := ptsr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("PodTraceSessionReconciler: %w", err)
	}

	ptr := &PodTraceReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		SystemNamespace: opts.SystemNamespace,
	}
	if err := ptr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("PodTraceReconciler: %w", err)
	}

	ecr := &ExporterConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := ecr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("ExporterConfigReconciler: %w", err)
	}

	pscr := &PodTraceScheduleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := pscr.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("PodTraceScheduleReconciler: %w", err)
	}

	return nil
}
