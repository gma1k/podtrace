package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/pkg/exporter/bundle"
)

// applyExporterFromFile parses a bundle YAML (typically mounted from an
// operator-maintained ConfigMap) and populates the process-global
// config.* exporter knobs. Used so the session Job, agent, and a local
// podtrace invocation all consume identical exporter config — the CLI
// path this function enables is --exporter-from-file.
//
// Credentials (Splunk HEC token, DataDog API key, OTLP Secret-backed
// header) may arrive in a sibling file or an environment variable; we
// read both sources.
func applyExporterFromFile(path string) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from a CLI flag, intentional caller-supplied path.
	if err != nil {
		return fmt.Errorf("read exporter file: %w", err)
	}
	p, err := bundle.FromYAML(raw)
	if err != nil {
		return err
	}

	// Credential loading. When the operator mounts the companion Secret
	// at a sibling path, or sets PODTRACE_EXPORTER_CREDENTIAL, we fold
	// the value into the payload before translating.
	if envCred := os.Getenv("PODTRACE_EXPORTER_CREDENTIAL"); envCred != "" {
		p.Credential = []byte(envCred)
	} else if credPath := os.Getenv("PODTRACE_EXPORTER_CREDENTIAL_FILE"); credPath != "" {
		cred, err := os.ReadFile(credPath) // #nosec G304,G703 -- operator-supplied credential path via env var.
		switch {
		case err == nil:
			p.Credential = cred
		case errors.Is(err, os.ErrNotExist):
		default:
			return fmt.Errorf("read exporter credential file: %w", err)
		}
	}

	applyPayloadToConfig(p)
	config.TracingEnabled = true
	return nil
}

// applyPayloadToConfig translates a bundle.Payload into the process-
// global config.* knobs the existing tracing manager reads on startup.
// Split out so tests can exercise it without touching the filesystem.
func applyPayloadToConfig(p *bundle.Payload) {
	if p == nil {
		return
	}
	switch p.Type {
	case bundle.TypeOTLP:
		config.OTLPEndpoint = p.Endpoint
	case bundle.TypeJaeger:
		config.JaegerEndpoint = p.Endpoint
	case bundle.TypeZipkin:
		config.ZipkinEndpoint = p.Endpoint
	case bundle.TypeSplunk:
		config.SplunkEndpoint = p.Endpoint
		if len(p.Credential) > 0 {
			config.SplunkToken = string(p.Credential)
		}
	case bundle.TypeDataDog:
		config.DataDogEndpoint = p.Endpoint
		if len(p.Credential) > 0 {
			config.DataDogAPIKey = string(p.Credential)
		}
	}
	if p.Sample > 0 {
		config.TracingSampleRate = p.Sample
	}
}
