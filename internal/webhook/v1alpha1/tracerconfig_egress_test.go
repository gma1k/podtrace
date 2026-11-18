package v1alpha1

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestTracerConfigWebhookRejectsAProxyWithCredentials(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "fleet"},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:v1",
			Egress: &podtracev1alpha1.EgressSpec{
				Proxy: &podtracev1alpha1.EgressProxySpec{HTTPSProxy: "http://user:secret@proxy:3128"},
			},
		},
	}
	_, err := (&TracerConfigCustomValidator{}).validate(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("a proxy URL with credentials must be rejected at admission, got %v", err)
	}
}

func TestTracerConfigWebhookAcceptsAValidEgress(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "fleet"},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:v1",
			Egress: &podtracev1alpha1.EgressSpec{
				BlockPrivateRanges: true,
				Proxy:              &podtracev1alpha1.EgressProxySpec{HTTPSProxy: "http://proxy:3128", NoProxy: ".svc"},
			},
		},
	}
	if _, err := (&TracerConfigCustomValidator{}).validate(context.Background(), tc); err != nil {
		t.Fatalf("validate: %v", err)
	}
}
