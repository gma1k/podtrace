package main

import (
	"strings"
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// baseWatchOpts returns a minimally-valid watchOptions that individual tests
// mutate. SamplePercent defaults to -1 (unset), matching the flag default.
func baseWatchOpts() watchOptions {
	return watchOptions{
		Namespace:     "default",
		Exporter:      "default",
		SamplePercent: -1,
	}
}

func TestBuildPodTrace_AppMapsToWellKnownLabel(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "checkout"

	pt, err := buildPodTrace(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt.Name != "checkout" {
		t.Fatalf("name: got %q want %q", pt.Name, "checkout")
	}
	if pt.Namespace != "default" {
		t.Fatalf("namespace: got %q want %q", pt.Namespace, "default")
	}
	if pt.Spec.Selector == nil {
		t.Fatalf("selector is nil")
	}
	if got := pt.Spec.Selector.MatchLabels[appNameLabel]; got != "checkout" {
		t.Fatalf("selector[%s]: got %q want %q", appNameLabel, got, "checkout")
	}
	if len(pt.Spec.PodRefs) != 0 {
		t.Fatalf("podRefs must be empty (selector XOR podRefs webhook invariant), got %v", pt.Spec.PodRefs)
	}
	if pt.Spec.NamespaceSelector != nil {
		t.Fatalf("namespaceSelector should be nil without --all-namespaces, got %+v", pt.Spec.NamespaceSelector)
	}
	if pt.Spec.ExporterRef.Name != "default" {
		t.Fatalf("exporterRef: got %q want %q", pt.Spec.ExporterRef.Name, "default")
	}
}

func TestBuildPodTrace_LabelSelectorParsed(t *testing.T) {
	opts := baseWatchOpts()
	opts.Label = "app=api,tier=web"
	opts.Name = "api-web"

	pt, err := buildPodTrace(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt.Name != "api-web" {
		t.Fatalf("name: got %q want %q", pt.Name, "api-web")
	}
	ml := pt.Spec.Selector.MatchLabels
	if ml["app"] != "api" || ml["tier"] != "web" {
		t.Fatalf("matchLabels: got %v want app=api,tier=web", ml)
	}
}

func TestBuildPodTrace_AllNamespacesIsEmptySelector(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "checkout"
	opts.AllNamespaces = true

	pt, err := buildPodTrace(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt.Spec.NamespaceSelector == nil {
		t.Fatalf("namespaceSelector must be non-nil for --all-namespaces")
	}
	if len(pt.Spec.NamespaceSelector.MatchLabels) != 0 || len(pt.Spec.NamespaceSelector.MatchExpressions) != 0 {
		t.Fatalf("namespaceSelector must be empty, got %+v", pt.Spec.NamespaceSelector)
	}
}

func TestBuildPodTrace_NamespaceSelectorParsed(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "checkout"
	opts.NamespaceSelector = "team=payments"

	pt, err := buildPodTrace(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt.Spec.NamespaceSelector == nil || pt.Spec.NamespaceSelector.MatchLabels["team"] != "payments" {
		t.Fatalf("namespaceSelector: got %+v want team=payments", pt.Spec.NamespaceSelector)
	}
}

func TestBuildPodTrace_FiltersAndSample(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "checkout"
	opts.Filter = "dns,net"
	opts.SamplePercent = 25

	pt, err := buildPodTrace(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS, podtracev1alpha1.FilterNet}
	if len(pt.Spec.Filters) != len(want) {
		t.Fatalf("filters: got %v want %v", pt.Spec.Filters, want)
	}
	for i := range want {
		if pt.Spec.Filters[i] != want[i] {
			t.Fatalf("filters[%d]: got %q want %q", i, pt.Spec.Filters[i], want[i])
		}
	}
	if pt.Spec.SamplePercent == nil || *pt.Spec.SamplePercent != 25 {
		t.Fatalf("samplePercent: got %v want 25", pt.Spec.SamplePercent)
	}
}

func TestBuildPodTrace_SampleUnsetByDefault(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "checkout"

	pt, err := buildPodTrace(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt.Spec.SamplePercent != nil {
		t.Fatalf("samplePercent should be unset, got %v", *pt.Spec.SamplePercent)
	}
}

func TestBuildPodTrace_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*watchOptions)
		wantSub string
	}{
		{
			name:    "neither app nor label",
			mutate:  func(o *watchOptions) {},
			wantSub: "one of --app or --label",
		},
		{
			name:    "app and label together",
			mutate:  func(o *watchOptions) { o.AppName = "x"; o.Label = "a=b" },
			wantSub: "mutually exclusive",
		},
		{
			name:    "all-namespaces and namespace-selector together",
			mutate:  func(o *watchOptions) { o.AppName = "x"; o.AllNamespaces = true; o.NamespaceSelector = "team=p" },
			wantSub: "mutually exclusive",
		},
		{
			name:    "label without name",
			mutate:  func(o *watchOptions) { o.Label = "app=api" },
			wantSub: "--name is required",
		},
		{
			name:    "empty exporter",
			mutate:  func(o *watchOptions) { o.AppName = "x"; o.Exporter = "" },
			wantSub: "--exporter must not be empty",
		},
		{
			name:    "invalid label selector",
			mutate:  func(o *watchOptions) { o.Label = "=,,"; o.Name = "n" },
			wantSub: "invalid --label",
		},
		{
			name:    "invalid filter",
			mutate:  func(o *watchOptions) { o.AppName = "x"; o.Filter = "bogus" },
			wantSub: "invalid event filter",
		},
		{
			name:    "sample over 100",
			mutate:  func(o *watchOptions) { o.AppName = "x"; o.SamplePercent = 200 },
			wantSub: "--sample must be between 0 and 100",
		},
		{
			name:    "invalid derived name",
			mutate:  func(o *watchOptions) { o.AppName = "Bad_Name!" },
			wantSub: "invalid PodTrace name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseWatchOpts()
			tt.mutate(&opts)
			_, err := buildPodTrace(opts)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestMarshalPodTraceYAML_SetsTypeMeta(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "checkout"
	pt, err := buildPodTrace(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, err := marshalPodTraceYAML(pt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "kind: PodTrace") {
		t.Fatalf("yaml missing kind: PodTrace:\n%s", s)
	}
	if !strings.Contains(s, "apiVersion: podtrace.io/v1alpha1") {
		t.Fatalf("yaml missing apiVersion:\n%s", s)
	}
}
