package v1alpha1_test

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestExamples_RoundTrip parses every file under examples/ and
// deserializes each YAML document into the Go type named by its
// apiVersion+kind. A drift between the type definition and the example
// manifest (renamed field, changed enum, missing required marker) fires
// as a decode error here — no apiserver needed, and far faster than
// envtest or a kind cluster.
//
// This is the single load-bearing check that keeps examples/*.yaml from
// rotting as the CRD schema evolves.
func TestExamples_RoundTrip(t *testing.T) {
	exDir := findExamplesDir(t)
	entries, err := os.ReadDir(exDir)
	if err != nil {
		t.Fatalf("readdir %s: %v", exDir, err)
	}

	// Build a decoder that knows both core/v1 (for the example Secrets)
	// and podtrace.io/v1alpha1. Using scheme.Scheme is the standard
	// controller-runtime pattern for mixed-type YAML.
	utilruntime.Must(podtracev1alpha1.AddToScheme(scheme.Scheme))
	decoder := scheme.Codecs.UniversalDeserializer()

	expectedKinds := map[string]bool{
		"PodTrace":        false,
		"PodTraceSession": false,
		"ExporterConfig":  false,
		"TracerConfig":    false,
		"Secret":          false,
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(exDir, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			docs := splitYAMLDocuments(raw)
			if len(docs) == 0 {
				t.Fatalf("no YAML documents found in %s", path)
			}
			for i, doc := range docs {
				if !hasNonCommentContent(doc) {
					continue
				}
				obj, _, err := decoder.Decode(doc, nil, nil)
				if err != nil {
					t.Fatalf("doc[%d] decode: %v", i, err)
				}
				kind := obj.GetObjectKind().GroupVersionKind().Kind
				if _, known := expectedKinds[kind]; !known {
					t.Errorf("doc[%d] unexpected kind %q", i, kind)
					continue
				}
				expectedKinds[kind] = true

				if err := validateStructuralNotEmpty(obj, kind); err != nil {
					t.Errorf("doc[%d] %s: %v", i, kind, err)
				}
			}
		})
	}

	// Every example-relevant kind should have appeared at least once
	// across the examples directory. A fresh user running through the
	// README should see all five resource types demonstrated.
	for kind, seen := range expectedKinds {
		if !seen {
			t.Errorf("no example demonstrates kind %q", kind)
		}
	}
}

// findExamplesDir walks up from the test's working directory until it
// finds the repo's examples/ directory. Works whether `go test` runs
// from api/v1alpha1 or the repo root.
func findExamplesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "examples")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate examples/ directory from test working dir")
	return ""
}

// hasNonCommentContent reports whether a YAML doc contains any non-empty,
// non-comment line. The multi-doc reader yields the leading comment
// block of a file (before the first "---") as its own "document"; we
// skip those rather than trying to decode them.
func hasNonCommentContent(doc []byte) bool {
	for _, line := range strings.Split(string(doc), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return true
	}
	return false
}

// splitYAMLDocuments delegates to apimachinery's multi-doc YAML reader.
// Example manifests frequently chain Secret + ExporterConfig in a
// single file separated by "---"; we must honor that.
func splitYAMLDocuments(raw []byte) [][]byte {
	var docs [][]byte
	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		doc, err := reader.Read()
		if err != nil {
			break
		}
		docs = append(docs, doc)
	}
	return docs
}

// validateStructuralNotEmpty catches silent-failure modes where the
// decoder accepts the doc but ends up with empty mandatory fields.
func validateStructuralNotEmpty(obj runtime.Object, kind string) error {
	switch o := obj.(type) {
	case *podtracev1alpha1.PodTrace:
		if o.Name == "" {
			return fmt.Errorf("metadata.name empty")
		}
		if o.Spec.ExporterRef.Name == "" {
			return fmt.Errorf("spec.exporterRef.name empty")
		}
	case *podtracev1alpha1.PodTraceSession:
		if o.Name == "" {
			return fmt.Errorf("metadata.name empty")
		}
		if o.Spec.Duration.Duration <= 0 {
			return fmt.Errorf("spec.duration not positive")
		}
		if o.Spec.ExporterRef.Name == "" {
			return fmt.Errorf("spec.exporterRef.name empty")
		}
	case *podtracev1alpha1.ExporterConfig:
		if o.Name == "" {
			return fmt.Errorf("metadata.name empty")
		}
		if o.Spec.Type == "" {
			return fmt.Errorf("spec.type empty")
		}
	case *podtracev1alpha1.TracerConfig:
		if o.Name == "" {
			return fmt.Errorf("metadata.name empty")
		}
		if o.Spec.Image == "" {
			return fmt.Errorf("spec.image empty")
		}
	case *corev1.Secret:
		if o.Name == "" {
			return fmt.Errorf("metadata.name empty")
		}
	default:
		return fmt.Errorf("no structural check for kind %q (%T)", kind, o)
	}
	return nil
}

