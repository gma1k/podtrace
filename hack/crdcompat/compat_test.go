package main

import (
	"os"
	"path/filepath"
	"testing"
)

func crdYAML(versions string) []byte {
	return []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: podtracesessions.podtrace.io
spec:
  group: podtrace.io
  versions:
` + versions)
}

func oneVersion(name string, served bool, properties string) string {
	servedValue := "false"
	if served {
		servedValue = "true"
	}
	return `  - name: ` + name + `
    served: ` + servedValue + `
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
` + properties
}

func changePaths(changes []Change) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, string(c.Kind)+" "+c.Path)
	}
	return out
}

func requireChanges(t *testing.T, changes []Change, want ...string) {
	t.Helper()
	got := changePaths(changes)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAddingAnOptionalFieldIsNotBreaking(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              maxEventsPerSecond: {type: integer}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes)
}

func TestRemovingAFieldIsBreaking(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              paused: {type: boolean}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "field removed spec.paused")
}

func TestRenameIsReportedAsRemovalOfTheOldPath(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          status:
            type: object
            properties:
              phase: {type: string}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          status:
            type: object
            properties:
              state: {type: string}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "field removed status.phase")
}

func TestRestructuringAFieldIsBreaking(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              sampling:
                type: object
                properties:
                  percent: {type: integer}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "field removed spec.samplePercent")
}

func TestChangingAFieldTypeIsBreaking(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: string}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "type changed spec.samplePercent")
	if changes[0].Detail != "integer -> string" {
		t.Fatalf("detail = %q", changes[0].Detail)
	}
}

func TestRemovingAServedVersionIsBreaking(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`) + oneVersion("v1beta1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	after := crdYAML(oneVersion("v1beta1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "served version removed v1alpha1")
}

func TestUnservedVersionsAreIgnored(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", false, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              paused: {type: boolean}
`))
	after := crdYAML(oneVersion("v1alpha1", false, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes)
}

func TestIdenticalSchemasAcrossTwoServedVersionsPass(t *testing.T) {
	identical := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`) + oneVersion("v1beta1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))

	changes, err := Compare(identical, identical)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes)
}

func TestNestedFieldRemovalReportsTheFullPath(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              exporterRef:
                type: object
                properties:
                  name: {type: string}
                  namespace: {type: string}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              exporterRef:
                type: object
                properties:
                  name: {type: string}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "field removed spec.exporterRef.namespace")
}

func TestListElementTypeChangeIsBreaking(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              filters:
                type: array
                items: {type: string}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              filters:
                type: array
                items: {type: integer}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "type changed spec.filters[]")
}

func TestMapValueTypeChangeIsBreaking(t *testing.T) {
	before := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              labels:
                type: object
                additionalProperties: {type: string}
`))
	after := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              labels:
                type: object
                additionalProperties: {type: integer}
`))

	changes, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "type changed spec.labels{}")
}

func TestMalformedManifestIsAnError(t *testing.T) {
	_, err := Compare([]byte("this: [is: not: valid"), crdYAML(oneVersion("v1alpha1", true, "")))
	if err == nil {
		t.Fatal("expected an error for a malformed manifest")
	}
}

func TestRunComparesEveryManifestInTheDirectory(t *testing.T) {
	baseDir := t.TempDir()
	headDir := t.TempDir()

	unchanged := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	regressed := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              paused: {type: boolean}
`))

	write := func(dir, name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(baseDir, "podtrace.io_podtraces.yaml", regressed)
	write(headDir, "podtrace.io_podtraces.yaml", unchanged)
	write(baseDir, "podtrace.io_exporterconfigs.yaml", unchanged)
	write(headDir, "podtrace.io_exporterconfigs.yaml", unchanged)

	changes, err := run(baseDir, headDir)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "field removed spec.paused")
}

func TestRunFlagsADeletedManifest(t *testing.T) {
	baseDir := t.TempDir()
	headDir := t.TempDir()

	body := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	if err := os.WriteFile(filepath.Join(baseDir, "podtrace.io_podtraces.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	changes, err := run(baseDir, headDir)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "served version removed podtrace.io_podtraces.yaml")
}

func TestNewManifestsAreNotBreaking(t *testing.T) {
	baseDir := t.TempDir()
	headDir := t.TempDir()

	body := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	if err := os.WriteFile(filepath.Join(headDir, "podtrace.io_applicationtraces.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	changes, err := run(baseDir, headDir)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes)
}

func TestCommittedChartTemplatesAreParseable(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "deploy", "charts", "podtrace", "templates", "crds", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no committed CRD manifests found")
	}

	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parse(body)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
		if parsed.Metadata.Name == "" {
			t.Fatalf("%s: no metadata.name", filepath.Base(path))
		}
		served := servedSchemas(parsed)
		if len(served) == 0 {
			t.Fatalf("%s: no served versions", filepath.Base(path))
		}
		for version, fields := range served {
			if len(fields) == 0 {
				t.Fatalf("%s: %s has no fields", filepath.Base(path), version)
			}
		}
	}
}

func TestHelmControlLinesAreStripped(t *testing.T) {
	body := []byte(`{{- if .Values.crds.install }}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    {{- if .Values.crds.keep }}
    helm.sh/resource-policy: keep
    {{- end }}
  name: podtraces.podtrace.io
spec:
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              samplePercent: {type: integer}
{{- end }}
`)

	parsed, err := parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Metadata.Name != "podtraces.podtrace.io" {
		t.Fatalf("name = %q", parsed.Metadata.Name)
	}
	if _, ok := servedSchemas(parsed)["v1alpha1"]["spec.samplePercent"]; !ok {
		t.Fatal("spec.samplePercent not found")
	}
}
