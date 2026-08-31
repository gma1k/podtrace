package main

import (
	"os"
	"path/filepath"
	"testing"
)

func divergencePaths(found []Divergence) []string {
	out := make([]string, 0, len(found))
	for _, d := range found {
		out = append(out, d.Path)
	}
	return out
}

func requireDivergences(t *testing.T, found []Divergence, want ...string) {
	t.Helper()
	got := divergencePaths(found)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSingleServedVersionIsTriviallyIdentical(t *testing.T) {
	manifest := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))

	found, err := CheckIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found)
}

func TestIdenticalServedVersionsPass(t *testing.T) {
	body := `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              exporterRef:
                type: object
                properties:
                  name: {type: string}
`
	manifest := crdYAML(oneVersion("v1alpha1", true, body) + oneVersion("v1beta1", true, body))

	found, err := CheckIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found)
}

func TestFieldOnlyInTheNewVersionIsADivergence(t *testing.T) {
	manifest := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`) + oneVersion("v1beta1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              maxEventsPerSecond: {type: integer}
`))

	found, err := CheckIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found, "spec.maxEventsPerSecond")
	if found[0].Detail == "" {
		t.Fatal("divergence should say which version has the field")
	}
}

func TestFieldOnlyInTheOldVersionIsADivergence(t *testing.T) {
	manifest := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              paused: {type: boolean}
`) + oneVersion("v1beta1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))

	found, err := CheckIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found, "spec.paused")
}

func TestTypeDifferenceBetweenVersionsIsADivergence(t *testing.T) {
	manifest := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`) + oneVersion("v1beta1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: string}
`))

	found, err := CheckIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found, "spec.samplePercent")
	if found[0].Detail != "integer in v1alpha1, string in v1beta1" {
		t.Fatalf("detail = %q", found[0].Detail)
	}
}

func TestUnservedVersionsAreNotComparedForIdentity(t *testing.T) {
	manifest := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`) + oneVersion("v1beta1", false, `          spec:
            type: object
            properties:
              somethingElse: {type: string}
`))

	found, err := CheckIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found)
}

func TestThreeVersionsReportEachDifferenceOnce(t *testing.T) {
	base := `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`
	manifest := crdYAML(
		oneVersion("v1alpha1", true, base) +
			oneVersion("v1beta1", true, base) +
			oneVersion("v1beta2", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              extra: {type: string}
`))

	found, err := CheckIdentity(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found, "spec.extra")
}

func TestRunIdentityWalksTheDirectory(t *testing.T) {
	dir := t.TempDir()

	clean := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`))
	diverged := crdYAML(oneVersion("v1alpha1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
`) + oneVersion("v1beta1", true, `          spec:
            type: object
            properties:
              samplePercent: {type: integer}
              drift: {type: string}
`))

	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), clean, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), diverged, 0o600); err != nil {
		t.Fatal(err)
	}

	found, multiVersion, err := runIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if multiVersion != 1 {
		t.Fatalf("multiVersion = %d, want 1", multiVersion)
	}
	requireDivergences(t, found, "spec.drift")
}

func TestCommittedManifestsAreIdentityClean(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy", "charts", "podtrace", "templates", "crds")
	found, _, err := runIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("committed CRDs diverge across served versions: %v", divergencePaths(found))
	}
}
