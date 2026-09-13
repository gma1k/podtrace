package v1alpha1

import (
	"context"
	"strings"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func btfSourceError(t *testing.T, name string, spec podtracev1alpha1.TracerConfigSpec) error {
	t.Helper()
	_, err := tracerConfigValidator(t).ValidateCreate(context.Background(), tracerConfig(name, spec))
	return err
}

func TestFileBTFModeWithoutASourceIsRejected(t *testing.T) {
	err := btfSourceError(t, "file-nosource", podtracev1alpha1.TracerConfigSpec{
		BTFMode: podtracev1alpha1.BTFModeFile,
	})
	if err == nil {
		t.Fatal("btfMode=file with no btfSource was accepted.\n\nThe DaemonSet renders " +
			"without the mount, the agent falls back to host BTF, and on the node this " +
			"mode exists for that means stub types -- the same silent non-feature the " +
			"embedded mode was.")
	}
	if !strings.Contains(err.Error(), "btfSource") {
		t.Errorf("error %q does not name the missing field", err)
	}
}

func TestFileBTFModeAcceptsEitherSource(t *testing.T) {
	for name, src := range map[string]*podtracev1alpha1.BTFSource{
		"configmap": {ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"}},
		"hostpath":  {HostPath: "/var/lib/podtrace/vmlinux.btf"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := btfSourceError(t, "file-"+name, podtracev1alpha1.TracerConfigSpec{
				BTFMode:   podtracev1alpha1.BTFModeFile,
				BTFSource: src,
			}); err != nil {
				t.Errorf("rejected: %v", err)
			}
		})
	}
}

func TestBothBTFSourcesAtOnceIsRejected(t *testing.T) {
	err := btfSourceError(t, "file-both", podtracev1alpha1.TracerConfigSpec{
		BTFMode: podtracev1alpha1.BTFModeFile,
		BTFSource: &podtracev1alpha1.BTFSource{
			ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"},
			HostPath:  "/var/lib/podtrace/vmlinux.btf",
		},
	})
	if err == nil {
		t.Fatal("both sources were accepted; which blob loads would then depend on the " +
			"builder's evaluation order rather than on what the author wrote")
	}
}

func TestANamelessConfigMapSourceIsRejected(t *testing.T) {
	err := btfSourceError(t, "file-noname", podtracev1alpha1.TracerConfigSpec{
		BTFMode:   podtracev1alpha1.BTFModeFile,
		BTFSource: &podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{}},
	})
	if err == nil {
		t.Fatal("a ConfigMap source with no name was accepted")
	}
}

func TestABTFSourceWithoutFileModeIsRejected(t *testing.T) {
	for _, mode := range []podtracev1alpha1.BTFMode{
		"",
		podtracev1alpha1.BTFModeAuto,
		podtracev1alpha1.BTFModeHost,
		podtracev1alpha1.BTFModeEmbedded,
	} {
		err := btfSourceError(t, "src-"+string(mode)+"x", podtracev1alpha1.TracerConfigSpec{
			BTFMode: mode,
			BTFSource: &podtracev1alpha1.BTFSource{
				ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"},
			},
		})
		if err == nil {
			t.Errorf("btfMode %q accepted a btfSource it will never read.\n\nA staged blob "+
				"that is silently ignored reads as a configured feature, which is the "+
				"failure this whole change exists to remove.", mode)
		}
	}
}

func TestNoBTFSourceAndNoFileModeIsFine(t *testing.T) {
	for _, mode := range []podtracev1alpha1.BTFMode{
		"",
		podtracev1alpha1.BTFModeAuto,
		podtracev1alpha1.BTFModeHost,
	} {
		if err := btfSourceError(t, "plain-"+string(mode)+"x",
			podtracev1alpha1.TracerConfigSpec{BTFMode: mode}); err != nil {
			t.Errorf("btfMode %q rejected: %v", mode, err)
		}
	}
}

func TestValidateBTFSourceToleratesANilTracerConfig(t *testing.T) {
	if err := validateBTFSource(nil); err != nil {
		t.Errorf("validateBTFSource(nil) = %v, want nil", err)
	}
}
