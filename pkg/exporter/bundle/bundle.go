// Package bundle defines the wire format for exporter configuration that
// travels between the podtrace operator, agent, and CLI.
//
// One shared schema means all three consume exporter config identically:
//
//   - operator renders an ExporterConfig CR into ConfigMap.data
//     (key/value strings) plus an optional companion Secret.
//   - agent reads that ConfigMap and constructs its in-process exporter.
//   - CLI reads a YAML file mounted from the same ConfigMap (via
//     --exporter-from-file) and sets the equivalent config globals.
package bundle

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// CredentialKey is the fixed key under which the operator stores the
// resolved credential material in the companion Secret. Agents and CLI
// both read exactly this key; the operator abstracts any upstream
// SecretKeySelector into it.
const CredentialKey = "credential"

const CurrentVersion = "v1"

// Type names the exporter implementation a Payload targets.
type Type string

const (
	TypeOTLP    Type = "otlp"
	TypeJaeger  Type = "jaeger"
	TypeZipkin  Type = "zipkin"
	TypeSplunk  Type = "splunk"
	TypeDataDog Type = "datadog"
)

type Payload struct {
	Version string `yaml:"version,omitempty"`

	// Type selects the exporter implementation.
	Type Type `yaml:"type"`

	// Endpoint is the target URL or host:port. Required for all types.
	Endpoint string `yaml:"endpoint,omitempty"`

	// Protocol selects the OTLP transport (http | grpc). OTLP only.
	Protocol string `yaml:"protocol,omitempty"`

	// Insecure disables TLS for OTLP. OTLP only.
	Insecure bool `yaml:"insecure,omitempty"`

	// Site selects the DataDog intake region. DataDog only.
	Site string `yaml:"site,omitempty"`

	// Sample is the sample rate as a fraction in [0, 1]. The upstream
	// ExporterConfig spec carries an integer percent; Parse converts it.
	Sample float64 `yaml:"sample,omitempty"`

	// Headers are literal OTLP export headers. OTLP only.
	Headers map[string]string `yaml:"headers,omitempty"`

	// HeaderName names the OTLP header whose value is sourced from the
	// companion Secret's CredentialKey. Empty when no Secret-backed
	// header is configured.
	HeaderName string `yaml:"headerName,omitempty"`

	// Credential is the resolved secret material (Splunk token,
	// DataDog API key, or OTLP Secret-backed header value). Transport
	// is the companion Secret; Payload carries it opaquely.
	Credential []byte `yaml:"-"`

	// ResourceVer is the ConfigMap ResourceVersion the payload was read
	// from, used by agent-side caches to dedupe unchanged bundles. Not
	// serialized to YAML — only populated by ConfigMap readers.
	ResourceVer string `yaml:"-"`
}

// FromConfigMapData parses the flat ConfigMap data written by the
// operator into a structured Payload. Unknown keys are ignored.
func FromConfigMapData(data map[string]string) (*Payload, error) {
	if data == nil {
		return nil, fmt.Errorf("bundle: nil ConfigMap data")
	}
	if v := data["version"]; v != "" && v != CurrentVersion {
		return nil, fmt.Errorf("bundle: unsupported version %q (this build understands %q)", v, CurrentVersion)
	}
	p := &Payload{
		Version:    data["version"],
		Type:       Type(data["type"]),
		Endpoint:   data["endpoint"],
		Protocol:   data["protocol"],
		Site:       data["site"],
		HeaderName: data["header_secret_name"],
	}
	if v := data["insecure"]; v != "" {
		p.Insecure = v == "true"
	}
	if v := data["sample_percent"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("bundle: sample_percent %q not an integer: %w", v, err)
		}
		if n < 0 || n > 100 {
			return nil, fmt.Errorf("bundle: sample_percent %d out of range 0-100", n)
		}
		p.Sample = float64(n) / 100.0
	}
	for k, v := range data {
		if rest, ok := strings.CutPrefix(k, "headers."); ok {
			if p.Headers == nil {
				p.Headers = map[string]string{}
			}
			p.Headers[rest] = v
		}
	}
	return p, nil
}

// ToConfigMapData renders a Payload back into the flat ConfigMap schema.
// Inverse of FromConfigMapData for all fields operator-side bundle
// reconcilers care about. Sample is stored as an integer percent for
// stable round-trip with the CRD schema.
func ToConfigMapData(p *Payload) map[string]string {
	if p == nil {
		return nil
	}
	out := map[string]string{
		"version": CurrentVersion,
		"type":    string(p.Type),
	}
	if p.Endpoint != "" {
		out["endpoint"] = p.Endpoint
	}
	if p.Protocol != "" {
		out["protocol"] = p.Protocol
	}
	if p.Site != "" {
		out["site"] = p.Site
	}
	if p.HeaderName != "" {
		out["header_secret_name"] = p.HeaderName
	}
	if p.Insecure {
		out["insecure"] = "true"
	} else if p.Type == TypeOTLP {
		out["insecure"] = "false"
	}
	if p.Sample > 0 {
		percent := int(p.Sample*100 + 0.5)
		out["sample_percent"] = strconv.Itoa(percent)
	}
	// Deterministic key order is not an on-disk invariant (ConfigMap
	// keys are unordered), but tests compare rendered data maps and
	// sorted construction makes failure diffs readable.
	keys := make([]string, 0, len(p.Headers))
	for k := range p.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out["headers."+k] = p.Headers[k]
	}
	return out
}

// FromYAML parses a Payload from its YAML serialization. Used by the
// CLI's --exporter-from-file flag, which mounts a ConfigMap as a file.
func FromYAML(raw []byte) (*Payload, error) {
	var p Payload
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("bundle: parse YAML: %w", err)
	}
	if p.Version != "" && p.Version != CurrentVersion {
		return nil, fmt.Errorf("bundle: unsupported version %q (this build understands %q)", p.Version, CurrentVersion)
	}
	if p.Type == "" {
		return nil, fmt.Errorf("bundle: missing required field 'type'")
	}
	if p.Sample < 0 || p.Sample > 1 {
		return nil, fmt.Errorf("bundle: sample %v out of range 0-1", p.Sample)
	}
	return &p, nil
}

// ToYAML renders a Payload as YAML. The operator writes this shape into
// the Job's mounted ConfigMap so the CLI sees identical fields to what
// the agent sees via FromConfigMapData.
func ToYAML(p *Payload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("bundle: nil payload")
	}
	out := *p
	out.Version = CurrentVersion
	return yaml.Marshal(&out)
}
