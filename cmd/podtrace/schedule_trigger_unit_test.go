package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunScheduleTrigger_RequiresName(t *testing.T) {
	err := runScheduleTrigger(context.Background(), scheduleTriggerOptions{
		Name:      "",
		Namespace: "obs",
	})
	if err == nil || !strings.Contains(err.Error(), "schedule name is required") {
		t.Fatalf("expected schedule-name error, got %v", err)
	}
}

func TestRunScheduleTrigger_RequiresNamespace(t *testing.T) {
	err := runScheduleTrigger(context.Background(), scheduleTriggerOptions{
		Name:      "nightly",
		Namespace: "",
	})
	if err == nil || !strings.Contains(err.Error(), "--namespace is required") {
		t.Fatalf("expected namespace-required error, got %v", err)
	}
}

const unreachableKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: t
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: t
  context:
    cluster: t
    user: t
current-context: t
users:
- name: t
  user:
    token: x
`

func writeUnreachableKubeconfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(unreachableKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunScheduleTrigger_GetError(t *testing.T) {
	kubeconfig := writeUnreachableKubeconfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runScheduleTrigger(ctx, scheduleTriggerOptions{
		Name:       "nightly",
		Namespace:  "obs",
		Kubeconfig: kubeconfig,
	})
	if err == nil || !strings.Contains(err.Error(), "get PodTraceSchedule") {
		t.Fatalf("expected get-schedule error against unreachable API, got %v", err)
	}
}

func TestRunScheduleTrigger_InvalidKubeconfig(t *testing.T) {

	bad := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(bad, []byte("::not valid yaml::\n\t- broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runScheduleTrigger(context.Background(), scheduleTriggerOptions{
		Name:       "nightly",
		Namespace:  "obs",
		Kubeconfig: bad,
	})
	if err == nil || !strings.Contains(err.Error(), "load kubeconfig") {
		t.Fatalf("expected load-kubeconfig error, got %v", err)
	}
}
