package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestBuildSessionJobSpec_MainContainerHardened(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
	}
	spec := buildSessionJobSpec(minimalSession(), tc, "node-a", sessionTargets{})
	sc := spec.Template.Spec.Containers[0].SecurityContext

	if sc == nil {
		t.Fatal("main container SecurityContext is nil")
	}
	if sc.Privileged != nil && *sc.Privileged {
		t.Error("session main container must not be privileged (caps-only)")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("session main container must set allowPrivilegeEscalation=false")
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("session main container must set seccompProfile RuntimeDefault, got %+v", sc.SeccompProfile)
	}
}

func TestBuildSessionJobSpec_ReportUploaderSidecarLockedDown(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:   "ghcr.io/gma1k/podtrace:test",
			Session: podtracev1alpha1.SessionRuntimeSpec{SidecarUploader: true},
		},
	}
	s := minimalSession()
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ConfigMap: &corev1.LocalObjectReference{Name: "rep"},
	}
	spec := buildSessionJobSpec(s, tc, "node-a", sessionTargets{})

	var sidecar *corev1.Container
	for i := range spec.Template.Spec.InitContainers {
		if spec.Template.Spec.InitContainers[i].Name == "report-uploader" {
			sidecar = &spec.Template.Spec.InitContainers[i]
		}
	}
	if sidecar == nil {
		t.Fatal("report-uploader sidecar not found")
	}
	sc := sidecar.SecurityContext
	if sc == nil {
		t.Fatal("report-uploader sidecar has no SecurityContext")
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("sidecar must set runAsNonRoot=true")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("sidecar must set allowPrivilegeEscalation=false")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("sidecar must set readOnlyRootFilesystem=true")
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("sidecar must set seccompProfile RuntimeDefault, got %+v", sc.SeccompProfile)
	}
	if sc.Capabilities == nil || len(sc.Capabilities.Drop) == 0 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("sidecar must drop ALL capabilities, got %+v", sc.Capabilities)
	}
}
