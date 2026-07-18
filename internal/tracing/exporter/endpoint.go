package exporter

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/podtrace/podtrace/internal/config"
)

func validateExporterEndpoint(endpoint, defaultEndpoint string) (string, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		raw = defaultEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse exporter endpoint %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		u, err = url.Parse("http://" + raw)
		if err != nil {
			return "", fmt.Errorf("parse exporter endpoint %q: %w", raw, err)
		}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("exporter endpoint scheme must be http or https, got %q", u.Scheme)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) && !config.ExporterAllowInsecureNonLoopback() {
		return "", fmt.Errorf(
			"refusing cleartext http to non-loopback host %q: it would leak exporter credentials on the wire; use https:// or set PODTRACE_EXPORTER_INSECURE=1",
			u.Hostname())
	}
	return u.String(), nil
}
