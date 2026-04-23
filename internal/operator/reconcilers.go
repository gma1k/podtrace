package operator

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
)

// registerReconcilers wires all three reconcilers onto the manager.
// Order does not matter — the manager starts them in parallel — but we
// construct them in dependency order (TracerConfig first, then Session,
// then PodTrace) so a stack trace points at the failing one.
func registerReconcilers(mgr ctrl.Manager, opts Options) error {
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

	return nil
}
