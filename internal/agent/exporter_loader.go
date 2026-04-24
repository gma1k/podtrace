package agent

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/podtrace/podtrace/internal/operator"
	"github.com/podtrace/podtrace/pkg/exporter/bundle"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// BundlePayload is an alias for bundle.Payload so existing agent callers
// keep their familiar type name. New code should import
// pkg/exporter/bundle directly.
type BundlePayload = bundle.Payload

// LoadBundle reads the ConfigMap+optional-Secret pair the operator
// maintains in systemNamespace for the given PodTrace UID, and returns
// the parsed payload. Returns a NotFound error when the ConfigMap is
// missing so the caller can distinguish "not yet synced" from real
// failures.
func LoadBundle(ctx context.Context, c client.Client, systemNamespace string, podtraceUID types.UID) (*BundlePayload, error) {
	name := operator.ExporterBundleName(podtraceUID)

	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: systemNamespace}, &cm); err != nil {
		return nil, fmt.Errorf("get bundle ConfigMap: %w", err)
	}

	payload, err := bundle.FromConfigMapData(cm.Data)
	if err != nil {
		return nil, fmt.Errorf("parse bundle ConfigMap: %w", err)
	}
	payload.ResourceVer = cm.ResourceVersion

	// Credential Secret is only present when the exporter needed one
	// (Splunk HEC token, DataDog API key, or an OTLP Secret-backed
	// header). NotFound is non-fatal and returns a credential-less
	// payload — valid for credential-less exporters like Jaeger/Zipkin.
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: systemNamespace}, &sec); err == nil {
		payload.Credential = sec.Data[bundle.CredentialKey]
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get bundle Secret: %w", err)
	}

	return payload, nil
}

// BuildExporter turns a BundlePayload into a tracer.Exporter that
// accepts []*events.Event. Currently implements the OTLP backend only;
// Jaeger/Zipkin/Splunk/DataDog bundles return an explicit
// "not-yet-supported" error so the caller surfaces a clean Degraded
// condition instead of silently dropping traces.
//
// The sole caller (the agent's reconcile loop) converts the error
// into a per-CR NodeStatus.Message so the user sees it on
// kubectl describe.
func BuildExporter(payload *BundlePayload, crKey CRKey) (tracer.Exporter, error) {
	if payload == nil {
		return nil, fmt.Errorf("nil bundle payload")
	}
	switch payload.Type {
	case bundle.TypeOTLP:
		return newOTLPEventExporter(crKey, payload)
	case bundle.TypeJaeger, bundle.TypeZipkin, bundle.TypeSplunk, bundle.TypeDataDog:
		return nil, fmt.Errorf("exporter type %q not yet implemented in agent mode", payload.Type)
	default:
		return nil, fmt.Errorf("unknown exporter type %q", payload.Type)
	}
}
