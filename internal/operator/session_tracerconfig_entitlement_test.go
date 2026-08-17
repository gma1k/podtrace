package operator

import (
	"context"
	"errors"
	"strings"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestSessionRefCrossTenantWithoutConsentIsTerminal(t *testing.T) {
	r := sessionResolver(t, testTracerConfig("regulated", "img:regulated", "fleet-b", nil))

	_, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef("regulated"), []string{"n1"})
	var missing *errNoTracerConfig
	if !errors.As(err, &missing) {
		t.Fatalf("want errNoTracerConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "not entitled") {
		t.Errorf("error should explain the missing consent, got %q", err)
	}
}

func TestSessionRefCrossTenantWithConsentResolves(t *testing.T) {
	granted := testTracerConfig("regulated", "img:regulated", "fleet-b", nil)
	granted.Annotations = map[string]string{podtracev1alpha1.AllowSessionsFromAnnotation: "team-a"}
	r := sessionResolver(t, granted)

	got, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef("regulated"), []string{"n1"})
	if err != nil {
		t.Fatalf("a consented cross-tenant pin must resolve, got %v", err)
	}
	if name := got.forNode("n1").Name; name != "regulated" {
		t.Errorf("n1 resolved to %q, want regulated", name)
	}
}

func TestSessionRefOwnNamespacePinResolvesWithoutConsent(t *testing.T) {
	r := sessionResolver(t, testTracerConfig("local", "img:local", "team-a", nil))

	got, err := r.resolveSessionTracerConfigs(context.Background(), sessionWithRef("local"), []string{"n1"})
	if err != nil {
		t.Fatalf("a pin landing in the session's own namespace needs no grant, got %v", err)
	}
	if name := got.forNode("n1").Name; name != "local" {
		t.Errorf("n1 resolved to %q, want local", name)
	}
}
