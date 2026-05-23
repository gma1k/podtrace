package v1alpha1

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateObjectStoreReference is the admission-time check for
// spec.reportRef.objectStore.
func ValidateObjectStoreReference(ref *ObjectStoreReference) error {
	if ref == nil {
		return nil
	}
	if ref.URI == "" {
		return fmt.Errorf("spec.reportRef.objectStore.uri is required")
	}
	if err := validateObjectStoreURI(ref.URI); err != nil {
		return fmt.Errorf("spec.reportRef.objectStore.uri: %w", err)
	}
	return nil
}

// validateObjectStoreURI enforces the supported URI shapes.
func validateObjectStoreURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%q must include scheme and host", raw)
	}
	switch u.Scheme {
	case "s3", "gs":
	case "azblob":
		path := strings.TrimPrefix(u.Path, "/")
		if path == "" || strings.HasPrefix(path, "/") {
			return fmt.Errorf("azblob URI %q must include a container after the account", raw)
		}
	default:
		return fmt.Errorf("unsupported URI scheme %q (want s3, gs, or azblob)", u.Scheme)
	}
	return nil
}

// ValidateExporterConfigVariant enforces that the typed field matching
// spec.type is populated, and only that one.
func ValidateExporterConfigVariant(spec ExporterConfigSpec) error {
	present := map[ExporterType]bool{
		ExporterTypeOTLP:    spec.OTLP != nil,
		ExporterTypeJaeger:  spec.Jaeger != nil,
		ExporterTypeZipkin:  spec.Zipkin != nil,
		ExporterTypeSplunk:  spec.Splunk != nil,
		ExporterTypeDataDog: spec.DataDog != nil,
	}

	var populated []ExporterType
	for t, ok := range present {
		if ok {
			populated = append(populated, t)
		}
	}
	if len(populated) == 0 {
		return fmt.Errorf("spec.%s must be set when spec.type is %q", spec.Type, spec.Type)
	}
	if len(populated) > 1 {
		return fmt.Errorf("only one of spec.otlp/jaeger/zipkin/splunk/datadog may be set")
	}
	if populated[0] != spec.Type {
		return fmt.Errorf("spec.type %q does not match populated field spec.%s", spec.Type, populated[0])
	}
	return nil
}