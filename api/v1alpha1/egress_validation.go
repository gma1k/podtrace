package v1alpha1

import (
	"fmt"
	"net/url"
)

// ValidateEgress checks spec.egress beyond what the CRD schema can express:
// each proxy must parse as an http or https URL with a host and must not
// embed credentials, which would otherwise be rendered into pod specs.
func ValidateEgress(e *EgressSpec) error {
	if e == nil || e.Proxy == nil {
		return nil
	}
	p := e.Proxy
	if p.HTTPProxy == "" && p.HTTPSProxy == "" {
		return fmt.Errorf("spec.egress.proxy: set httpProxy, httpsProxy or both")
	}
	if err := validateProxyURL("spec.egress.proxy.httpProxy", p.HTTPProxy); err != nil {
		return err
	}
	return validateProxyURL("spec.egress.proxy.httpsProxy", p.HTTPSProxy)
}

func validateProxyURL(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s: scheme must be http or https, got %q", field, u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%s: missing host", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s: must not carry credentials; they would be visible in the agent and session pod specs", field)
	}
	return nil
}
