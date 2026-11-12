package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func objectStoreSession(uri string) *podtracev1alpha1.PodTraceSession {
	s := minimalSession()
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: uri},
	}
	return s
}

func uploaderTracerConfig() *podtracev1alpha1.TracerConfig {
	return &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:   "ghcr.io/gma1k/podtrace:test",
			Session: podtracev1alpha1.SessionRuntimeSpec{SidecarUploader: true},
		},
	}
}

func reportToArgs(spec corev1.PodSpec) map[string]string {
	out := map[string]string{}
	collect := func(c corev1.Container) {
		for i := 0; i+1 < len(c.Args); i++ {
			if c.Args[i] == "--report-to" {
				out[c.Name] = c.Args[i+1]
			}
		}
	}
	for _, c := range spec.Containers {
		collect(c)
	}
	for _, c := range spec.InitContainers {
		collect(c)
	}
	return out
}

func TestBuildSessionJobSpecExactKeyPerNodeOnMultiNodeSession(t *testing.T) {
	s := objectStoreSession("s3://bucket/reports/fixed.txt")
	targets := sessionTargets{Nodes: []string{"node-a", "node-b"}}

	for node, want := range map[string]string{
		"node-a": "s3://bucket/reports/fixed-node-a.txt",
		"node-b": "s3://bucket/reports/fixed-node-b.txt",
	} {
		args := reportToArgs(buildSessionJobSpec(s, uploaderTracerConfig(), node, targets).Template.Spec)
		if args["report-uploader"] != want {
			t.Errorf("%s uploader --report-to = %q, want %q", node, args["report-uploader"], want)
		}
		if args[sessionContainerName] != want {
			t.Errorf("%s session --report-to = %q, want %q", node, args[sessionContainerName], want)
		}
	}
}

func TestBuildSessionJobSpecExactKeyUnchangedOnSingleNodeSession(t *testing.T) {
	s := objectStoreSession("s3://bucket/reports/fixed.txt")
	targets := sessionTargets{Nodes: []string{"node-a"}}

	args := reportToArgs(buildSessionJobSpec(s, uploaderTracerConfig(), "node-a", targets).Template.Spec)
	if args["report-uploader"] != "s3://bucket/reports/fixed.txt" {
		t.Fatalf("single-node uploader --report-to = %q, want the exact key", args["report-uploader"])
	}
}

func TestBuildSessionJobSpecPrefixUnchangedOnMultiNodeSession(t *testing.T) {
	s := objectStoreSession("s3://bucket/reports/")
	targets := sessionTargets{Nodes: []string{"node-a", "node-b"}}

	args := reportToArgs(buildSessionJobSpec(s, uploaderTracerConfig(), "node-b", targets).Template.Spec)
	if args["report-uploader"] != "s3://bucket/reports/" {
		t.Fatalf("prefix uploader --report-to = %q, want the prefix unchanged", args["report-uploader"])
	}
}

func TestBuildSessionJobSpecConfigMapSinkUnchangedOnMultiNodeSession(t *testing.T) {
	s := minimalSession()
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ConfigMap: &corev1.LocalObjectReference{Name: "rep"},
	}
	targets := sessionTargets{Nodes: []string{"node-a", "node-b"}}

	args := reportToArgs(buildSessionJobSpec(s, uploaderTracerConfig(), "node-a", targets).Template.Spec)
	if args[sessionContainerName] != "configmap/"+s.Namespace+"/rep" {
		t.Fatalf("configmap --report-to = %q, want it unchanged", args[sessionContainerName])
	}
}
