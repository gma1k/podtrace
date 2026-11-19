package operator

import (
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func configMapUncached(t *testing.T, cacheOptions *client.CacheOptions) bool {
	t.Helper()
	if cacheOptions == nil {
		return false
	}
	for _, obj := range cacheOptions.DisableFor {
		if _, ok := obj.(*corev1.ConfigMap); ok {
			return true
		}
	}
	return false
}

func TestUncachedClientOptions_ConfigMapsBypassTheCache(t *testing.T) {
	if opts := uncachedClientOptions(); !configMapUncached(t, opts.Cache) {
		t.Fatalf("DisableFor = %v, want ConfigMaps read from the API server", opts.Cache)
	}
}

func TestManagerOptions_ReadsConfigMapsUncached(t *testing.T) {
	scheme := newOperatorScheme(t)
	opts := DefaultOptions()
	opts.WebhookCertDir = ""
	got := managerOptions(opts, scheme, http.NotFoundHandler())

	if !configMapUncached(t, got.Client.Cache) {
		t.Fatal("the manager client must read ConfigMaps from the API server")
	}
	for cached := range got.Cache.ByObject {
		if _, isConfigMap := cached.(*corev1.ConfigMap); isConfigMap {
			t.Fatal("ConfigMaps must not get a cache entry")
		}
	}
	if got.Scheme != scheme {
		t.Error("the manager must use the given scheme")
	}
	if _, ok := got.Metrics.ExtraHandlers[CorrelationsPath]; !ok {
		t.Errorf("metrics server is missing the %s handler", CorrelationsPath)
	}
	if got.GracefulShutdownTimeout != nil || got.WebhookServer != nil || got.Cache.SyncPeriod != nil {
		t.Errorf("unset options must stay unset: shutdown=%v webhook=%v sync=%v",
			got.GracefulShutdownTimeout, got.WebhookServer, got.Cache.SyncPeriod)
	}
}

func TestManagerOptions_AppliesOptionalSettings(t *testing.T) {
	opts := DefaultOptions()
	opts.GracefulShutdownTimeout = 20 * time.Second
	opts.SyncPeriod = 5 * time.Minute
	opts.WebhookCertDir = t.TempDir()

	got := managerOptions(opts, newOperatorScheme(t), http.NotFoundHandler())

	if got.GracefulShutdownTimeout == nil || *got.GracefulShutdownTimeout != 20*time.Second {
		t.Errorf("GracefulShutdownTimeout = %v, want 20s", got.GracefulShutdownTimeout)
	}
	if got.Cache.SyncPeriod == nil || *got.Cache.SyncPeriod != 5*time.Minute {
		t.Errorf("SyncPeriod = %v, want 5m", got.Cache.SyncPeriod)
	}
	if got.WebhookServer == nil {
		t.Error("a webhook cert dir must start the webhook server")
	}
	if len(got.Cache.ByObject) != 4 {
		t.Errorf("cache.ByObject has %d entries, want the 4 trimmed or filtered kinds", len(got.Cache.ByObject))
	}
}
