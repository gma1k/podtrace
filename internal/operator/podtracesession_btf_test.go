package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func sessionPodSpec(t *testing.T, tc *podtracev1alpha1.TracerConfig) corev1.PodSpec {
	t.Helper()
	return buildSessionJobSpec(minimalSession(), tc, "node-a", sessionTargets{}).Template.Spec
}

func sessionMainContainer(t *testing.T, spec corev1.PodSpec) corev1.Container {
	t.Helper()
	for _, c := range spec.Containers {
		if c.Name == "podtrace" {
			return c
		}
	}
	t.Fatal("no podtrace container in the session Job")
	return corev1.Container{}
}

func TestASessionJobReceivesTheSuppliedBTF(t *testing.T) {
	spec := sessionPodSpec(t, &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			BTFMode: podtracev1alpha1.BTFModeFile,
			BTFSource: &podtracev1alpha1.BTFSource{
				ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"},
			},
		},
	})
	main := sessionMainContainer(t, spec)

	got, ok := envValue(main.Env, "PODTRACE_BTF_FILE")
	if !ok || got != "/etc/podtrace/btf/vmlinux.btf" {
		t.Errorf("PODTRACE_BTF_FILE = %q (set=%v).\n\nThe session Job loads its own BPF "+
			"collection, so btfMode=file has to reach it too. Without this the agent works "+
			"on a BTF-less node while every session against that node falls back to stub "+
			"types -- a half-configured cluster is worse than an unconfigured one.", got, ok)
	}
	if _, ok := mountNamed(main, "btf-file"); !ok {
		t.Error("no btf-file mount; the env var points at a path that does not exist")
	}

	found := false
	for _, v := range spec.Volumes {
		if v.Name == "btf-file" {
			found = true
		}
	}
	if !found {
		t.Error("no btf-file volume on the session Job pod")
	}
}

func TestASessionJobWithoutFileModeMountsNoBlob(t *testing.T) {
	for _, mode := range []podtracev1alpha1.BTFMode{
		"",
		podtracev1alpha1.BTFModeAuto,
		podtracev1alpha1.BTFModeHost,
		podtracev1alpha1.BTFModeEmbedded,
	} {
		spec := sessionPodSpec(t, &podtracev1alpha1.TracerConfig{
			Spec: podtracev1alpha1.TracerConfigSpec{BTFMode: mode},
		})
		if _, ok := envValue(sessionMainContainer(t, spec).Env, "PODTRACE_BTF_FILE"); ok {
			t.Errorf("btfMode %q set PODTRACE_BTF_FILE on the session Job", mode)
		}
		for _, v := range spec.Volumes {
			if v.Name == "btf-file" {
				t.Errorf("btfMode %q mounted a btf-file volume on the session Job", mode)
			}
		}
	}
}

func TestASessionJobWithNoTracerConfigMountsNoBlob(t *testing.T) {
	spec := buildSessionJobSpec(minimalSession(), nil, "node-a", sessionTargets{}).Template.Spec
	for _, v := range spec.Volumes {
		if v.Name == "btf-file" {
			t.Error("a btf-file volume was rendered with no TracerConfig to read it from")
		}
	}
}
