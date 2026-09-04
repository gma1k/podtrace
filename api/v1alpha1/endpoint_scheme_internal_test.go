package v1alpha1

import "testing"

func TestEndpointCheckIsANoOpWhenNoVariantIsPopulated(t *testing.T) {
	if err := validateExporterEndpoint(ExporterConfigSpec{Type: ExporterTypeOTLP}); err != nil {
		t.Errorf("validateExporterEndpoint returned %v for a spec with no variant set. The "+
			"caller already reports the missing variant, so this must fall through rather than "+
			"produce a second, more confusing error", err)
	}
}
