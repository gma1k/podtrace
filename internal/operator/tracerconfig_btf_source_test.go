package operator

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func agentContainer(t *testing.T, spec podtracev1alpha1.TracerConfigSpec) corev1.Container {
	t.Helper()
	ds := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{Spec: spec}, "podtrace-system")
	if len(ds.Template.Spec.Containers) != 1 {
		t.Fatalf("got %d containers, want 1", len(ds.Template.Spec.Containers))
	}
	return ds.Template.Spec.Containers[0]
}

func volumeNamed(t *testing.T, spec podtracev1alpha1.TracerConfigSpec, name string) (corev1.Volume, bool) {
	t.Helper()
	ds := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{Spec: spec}, "podtrace-system")
	for _, v := range ds.Template.Spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

func mountNamed(c corev1.Container, name string) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

func fileModeSpec(src *podtracev1alpha1.BTFSource) podtracev1alpha1.TracerConfigSpec {
	return podtracev1alpha1.TracerConfigSpec{
		BTFMode:   podtracev1alpha1.BTFModeFile,
		BTFSource: src,
	}
}

func TestAConfigMapBTFSourceIsMountedAndPointedAt(t *testing.T) {
	spec := fileModeSpec(&podtracev1alpha1.BTFSource{
		ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"},
	})

	got, ok := envValue(agentContainer(t, spec).Env, "PODTRACE_BTF_FILE")
	if !ok || got != "/etc/podtrace/btf/vmlinux.btf" {
		t.Errorf("PODTRACE_BTF_FILE = %q (set=%v), want the default key under the mount dir; "+
			"the tracer reads this variable and nothing else", got, ok)
	}

	vol, ok := volumeNamed(t, spec, "btf-file")
	if !ok {
		t.Fatal("no btf-file volume; the env var would point at a path that does not exist")
	}
	if vol.ConfigMap == nil || vol.ConfigMap.Name != "node-btf" {
		t.Fatalf("volume source = %+v, want ConfigMap node-btf", vol.VolumeSource)
	}
	if len(vol.ConfigMap.Items) != 1 || vol.ConfigMap.Items[0].Key != "vmlinux.btf" {
		t.Errorf("items = %+v, want only the named key projected", vol.ConfigMap.Items)
	}

	mount, ok := mountNamed(agentContainer(t, spec), "btf-file")
	if !ok || mount.MountPath != "/etc/podtrace/btf" || !mount.ReadOnly {
		t.Errorf("mount = %+v, want a read-only mount at /etc/podtrace/btf", mount)
	}
}

func TestAConfigMapKeyOverridesTheDefault(t *testing.T) {
	spec := fileModeSpec(&podtracev1alpha1.BTFSource{
		ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf", Key: "5.11.0-1028-gcp.btf"},
	})

	got, _ := envValue(agentContainer(t, spec).Env, "PODTRACE_BTF_FILE")
	if got != "/etc/podtrace/btf/5.11.0-1028-gcp.btf" {
		t.Errorf("PODTRACE_BTF_FILE = %q, want the supplied key", got)
	}
}

func TestAHostPathBTFSourceIsMountedAsTheFileItself(t *testing.T) {
	spec := fileModeSpec(&podtracev1alpha1.BTFSource{HostPath: "/var/lib/podtrace/vmlinux.btf"})

	got, _ := envValue(agentContainer(t, spec).Env, "PODTRACE_BTF_FILE")
	if got != "/etc/podtrace/btf/vmlinux.btf" {
		t.Errorf("PODTRACE_BTF_FILE = %q, want the basename under the mount dir", got)
	}

	vol, ok := volumeNamed(t, spec, "btf-file")
	if !ok || vol.HostPath == nil {
		t.Fatalf("no hostPath volume: %+v", vol)
	}
	if vol.HostPath.Path != "/var/lib/podtrace/vmlinux.btf" {
		t.Errorf("hostPath = %q, want the supplied path", vol.HostPath.Path)
	}
	if vol.HostPath.Type == nil || *vol.HostPath.Type != corev1.HostPathFile {
		t.Errorf("hostPath type = %v, want File; a directory mount would expose whatever "+
			"else sits beside the blob to a privileged container", vol.HostPath.Type)
	}
}

func TestModesOtherThanFileMountNoBlob(t *testing.T) {
	for _, mode := range []podtracev1alpha1.BTFMode{
		"",
		podtracev1alpha1.BTFModeAuto,
		podtracev1alpha1.BTFModeHost,
		podtracev1alpha1.BTFModeEmbedded,
	} {
		spec := podtracev1alpha1.TracerConfigSpec{BTFMode: mode}
		if _, ok := envValue(agentContainer(t, spec).Env, "PODTRACE_BTF_FILE"); ok {
			t.Errorf("btfMode %q set PODTRACE_BTF_FILE; only file mode supplies a blob", mode)
		}
		if _, ok := volumeNamed(t, spec, "btf-file"); ok {
			t.Errorf("btfMode %q mounted a btf-file volume", mode)
		}
	}
}

func TestEmbeddedModeRendersExactlyLikeAuto(t *testing.T) {
	auto := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{BTFMode: podtracev1alpha1.BTFModeAuto},
	}, "podtrace-system")
	embedded := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{BTFMode: podtracev1alpha1.BTFModeEmbedded},
	}, "podtrace-system")

	if len(auto.Template.Spec.Volumes) != len(embedded.Template.Spec.Volumes) {
		t.Errorf("embedded rendered %d volumes and auto %d.\n\nembedded is deprecated and "+
			"inert, so it must resolve exactly as auto does; half-configuring it is the "+
			"behaviour the deprecation exists to end.",
			len(embedded.Template.Spec.Volumes), len(auto.Template.Spec.Volumes))
	}
}

func TestFileModeWithoutASourceMountsNothing(t *testing.T) {
	spec := podtracev1alpha1.TracerConfigSpec{BTFMode: podtracev1alpha1.BTFModeFile}

	if _, ok := envValue(agentContainer(t, spec).Env, "PODTRACE_BTF_FILE"); ok {
		t.Error("PODTRACE_BTF_FILE was set with no source to point it at.\n\nThe webhook " +
			"rejects this, but the chart ships webhook.enabled=false, so the builder must " +
			"not render a path that resolves to nothing.")
	}
	if _, ok := volumeNamed(t, spec, "btf-file"); ok {
		t.Error("a btf-file volume was rendered with no source")
	}
}

func TestFileModeWithAnUnusableSourceMountsNothing(t *testing.T) {
	for name, source := range map[string]*podtracev1alpha1.BTFSource{
		"neither field set":  {},
		"nameless configmap": {ConfigMap: &podtracev1alpha1.BTFConfigMapSource{}},
	} {
		t.Run(name, func(t *testing.T) {
			spec := fileModeSpec(source)

			if got, ok := envValue(agentContainer(t, spec).Env, "PODTRACE_BTF_FILE"); ok {
				t.Errorf("PODTRACE_BTF_FILE = %q from a source that names no blob.\n\nThe "+
					"webhook rejects this, but the chart ships webhook.enabled=false, so the "+
					"builder must not render a path that resolves to nothing.", got)
			}
			if _, ok := volumeNamed(t, spec, "btf-file"); ok {
				t.Error("a btf-file volume was rendered from a source that names no blob")
			}
			if _, ok := mountNamed(agentContainer(t, spec), "btf-file"); ok {
				t.Error("a btf-file mount was rendered from a source that names no blob")
			}
		})
	}
}

func TestTheReconciledMessageNamesTheBlobItLoaded(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  *podtracev1alpha1.BTFSource
		want string
	}{
		{"configmap", &podtracev1alpha1.BTFSource{
			ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"},
		}, "ConfigMap node-btf key vmlinux.btf"},
		{"hostpath", &podtracev1alpha1.BTFSource{
			HostPath: "/var/lib/podtrace/vmlinux.btf",
		}, "host path /var/lib/podtrace/vmlinux.btf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := reconciledMessageFor(&podtracev1alpha1.TracerConfig{Spec: fileModeSpec(tc.src)}, "")
			if !contains(msg, tc.want) {
				t.Errorf("Reconciled message = %q, want it to name %q; kubectl describe is "+
					"where an operator checks which blob was actually used", msg, tc.want)
			}
		})
	}
}

func TestFileModeWithNoUsableSourceIsCalledOutOnTheCR(t *testing.T) {
	for name, spec := range map[string]podtracev1alpha1.TracerConfigSpec{
		"no source at all": {BTFMode: podtracev1alpha1.BTFModeFile},
		"empty source": {
			BTFMode:   podtracev1alpha1.BTFModeFile,
			BTFSource: &podtracev1alpha1.BTFSource{},
		},
		"nameless configmap": {
			BTFMode:   podtracev1alpha1.BTFModeFile,
			BTFSource: &podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			msg := reconciledMessageFor(&podtracev1alpha1.TracerConfig{Spec: spec}, "")
			if !contains(msg, "names no usable blob") {
				t.Errorf("Reconciled message = %q, which does not say the mode is inert.\n\n"+
					"The chart ships webhook.enabled=false, so admission rejects nothing on a "+
					"default install and the CR's own status is the only place this surfaces. "+
					"Silent file mode is the same non-feature btfMode=embedded was.", msg)
			}
		})
	}
}

func TestTheConditionNeverClaimsABlobTheBuilderDidNotMount(t *testing.T) {
	for name, spec := range map[string]podtracev1alpha1.TracerConfigSpec{
		"nameless configmap": {
			BTFMode:   podtracev1alpha1.BTFModeFile,
			BTFSource: &podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{}},
		},
		"source without file mode": {
			BTFMode: podtracev1alpha1.BTFModeAuto,
			BTFSource: &podtracev1alpha1.BTFSource{
				ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tc := &podtracev1alpha1.TracerConfig{Spec: spec}
			env, _, _ := btfFileWiring(tc)
			msg := reconciledMessageFor(tc, "")

			if len(env) == 0 && contains(msg, "the agent loads BTF from") {
				t.Errorf("Reconciled message = %q claims a blob, but the builder mounted "+
					"none; the status would send an operator looking for a problem that is "+
					"not where it says", msg)
			}
		})
	}
}

func TestAMissingBlobIsReportedInsteadOfClaimedAsLoaded(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{Spec: fileModeSpec(&podtracev1alpha1.BTFSource{
		ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"},
	})}

	msg := reconciledMessageFor(tc, "ConfigMap podtrace-system/node-btf does not exist, so no agent can start")

	if contains(msg, "the agent loads BTF from") {
		t.Errorf("Reconciled message = %q claims the blob is loaded while it does not "+
			"exist.\n\nRendering the mount is not the same as the ConfigMap existing: the "+
			"agents sit in ContainerCreating behind a kubelet event while the CR an "+
			"operator reads says everything is fine.", msg)
	}
	if !contains(msg, "does not exist") {
		t.Errorf("Reconciled message = %q does not carry the reason", msg)
	}
}

func TestTheOperatorDetectsAMissingOrIncompleteBlob(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}

	present := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "node-btf", Namespace: "podtrace-system"},
		BinaryData: map[string][]byte{"vmlinux.btf": []byte("\x9f\xeb\x01\x00")},
	}
	viaData := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "via-data", Namespace: "podtrace-system"},
		Data:       map[string]string{"vmlinux.btf": "a blob supplied as text rather than binaryData"},
	}
	wrongKey := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong-key", Namespace: "podtrace-system"},
		BinaryData: map[string][]byte{"something-else": []byte("x")},
	}

	r := &TracerConfigReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(present, viaData, wrongKey).Build(),
	}

	for name, tc := range map[string]struct {
		source *podtracev1alpha1.BTFSource
		want   string
	}{
		"blob present":   {&podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "node-btf"}}, ""},
		"absent":         {&podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "nope"}}, "does not exist"},
		"wrong key":      {&podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "wrong-key"}}, "has no key"},
		"key under data": {&podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "via-data"}}, ""},
		"hostpath":       {&podtracev1alpha1.BTFSource{HostPath: "/var/lib/podtrace/vmlinux.btf"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := r.btfBlobProblem(context.Background(),
				&podtracev1alpha1.TracerConfig{Spec: fileModeSpec(tc.source)}, "podtrace-system")
			if tc.want == "" && got != "" {
				t.Errorf("problem = %q, want none", got)
			}
			if tc.want != "" && !contains(got, tc.want) {
				t.Errorf("problem = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

func TestOtherModesAreNotCheckedForABlob(t *testing.T) {
	r := &TracerConfigReconciler{}
	for _, mode := range []podtracev1alpha1.BTFMode{
		"", podtracev1alpha1.BTFModeAuto, podtracev1alpha1.BTFModeEmbedded,
	} {
		tc := &podtracev1alpha1.TracerConfig{
			Spec: podtracev1alpha1.TracerConfigSpec{BTFMode: mode},
		}
		if got := r.btfBlobProblem(context.Background(), tc, "podtrace-system"); got != "" {
			t.Errorf("btfMode %q reported %q; a nil client would have panicked if it "+
				"reached the lookup", mode, got)
		}
	}
}

func TestAnUnusableBlobSchedulesARecheck(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 scheme: %v", err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("appsv1 scheme: %v", err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("rbac scheme: %v", err)
	}
	if err := podtracev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("podtrace scheme: %v", err)
	}

	spec := fileModeSpec(&podtracev1alpha1.BTFSource{
		ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "absent"},
	})
	spec.Image = "ghcr.io/gma1k/podtrace:dev"
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       spec,
	}
	r := &TracerConfigReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(tc).WithStatusSubresource(tc).Build(),
		Scheme:          scheme,
		SystemNamespace: "podtrace-system",
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("no recheck was scheduled for an unusable blob.\n\nNothing watches the " +
			"ConfigMap, so creating it would not wake this reconciler and the condition " +
			"would keep reporting a problem the operator already fixed.")
	}
}

func TestBTFSourceDescriptionCoversEverySourceShape(t *testing.T) {
	for name, tc := range map[string]struct {
		source *podtracev1alpha1.BTFSource
		want   string
	}{
		"nil source":        {nil, "an unset source"},
		"empty source":      {&podtracev1alpha1.BTFSource{}, "an unset source"},
		"configmap default": {&podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "cm"}}, "ConfigMap cm key vmlinux.btf"},
		"configmap key":     {&podtracev1alpha1.BTFSource{ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "cm", Key: "k.btf"}}, "ConfigMap cm key k.btf"},
		"hostpath":          {&podtracev1alpha1.BTFSource{HostPath: "/b.btf"}, "host path /b.btf"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := btfSourceDescription(tc.source); got != tc.want {
				t.Errorf("btfSourceDescription = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReconciledMessageForANilTracerConfigIsPlain(t *testing.T) {
	if got := reconciledMessageFor(nil, ""); got != "agent infrastructure reconciled" {
		t.Errorf("reconciledMessageFor(nil) = %q, want the bare message", got)
	}
}

func TestBlobLookupFailuresAreNotReportedAsProblems(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	r := &TracerConfigReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					return apierrors.NewServiceUnavailable("apiserver is having a moment")
				},
			}).Build(),
	}

	got := r.btfBlobProblem(context.Background(),
		&podtracev1alpha1.TracerConfig{Spec: fileModeSpec(&podtracev1alpha1.BTFSource{
			ConfigMap: &podtracev1alpha1.BTFConfigMapSource{Name: "cm"},
		})}, "podtrace-system")

	if got != "" {
		t.Errorf("problem = %q from a transient read failure.\n\nA blip against the "+
			"apiserver is not evidence the blob is missing, and reporting it as one would "+
			"flap the condition against a fleet that is perfectly healthy.", got)
	}
}

func TestABTFSourceWithAnEmptyConfigMapNameIsNotLookedUp(t *testing.T) {
	r := &TracerConfigReconciler{}
	got := r.btfBlobProblem(context.Background(),
		&podtracev1alpha1.TracerConfig{Spec: fileModeSpec(&podtracev1alpha1.BTFSource{
			ConfigMap: &podtracev1alpha1.BTFConfigMapSource{},
		})}, "podtrace-system")

	if got != "" {
		t.Errorf("problem = %q; a nil client would have panicked if it reached the lookup", got)
	}
}
