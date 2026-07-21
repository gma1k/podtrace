package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunWatch_PrintOnlyPodTrace(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "checkout"
	opts.PrintOnly = true

	if err := runWatch(context.Background(), opts); err != nil {
		t.Fatalf("print-only PodTrace should succeed, got %v", err)
	}
}

func TestRunWatch_PrintOnlyApplicationTrace(t *testing.T) {
	opts := baseWatchOpts()
	opts.AppName = "shop"
	opts.Application = true
	opts.PrintOnly = true

	if err := runWatch(context.Background(), opts); err != nil {
		t.Fatalf("print-only ApplicationTrace should succeed, got %v", err)
	}
}

func TestRunWatch_BuildPodTraceError(t *testing.T) {
	opts := baseWatchOpts()

	err := runWatch(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "one of --app or --label") {
		t.Fatalf("expected build error surfaced from runWatch, got %v", err)
	}
}

func TestRunWatch_BuildApplicationTraceError(t *testing.T) {
	opts := baseWatchOpts()
	opts.Application = true

	err := runWatch(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "one of --app or --label") {
		t.Fatalf("expected application build error surfaced from runWatch, got %v", err)
	}
}

func TestRunWatch_ExporterConfigCheckError(t *testing.T) {

	kubeconfig := writeUnreachableKubeconfig(t)

	opts := baseWatchOpts()
	opts.AppName = "checkout"
	opts.Kubeconfig = kubeconfig

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runWatch(ctx, opts)
	if err == nil || !strings.Contains(err.Error(), "check ExporterConfig") {
		t.Fatalf("expected ExporterConfig check error against unreachable API, got %v", err)
	}
}

func TestRunWatch_InvalidKubeconfig(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(bad, []byte("::not valid yaml::\n\t- broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := baseWatchOpts()
	opts.AppName = "checkout"
	opts.Kubeconfig = bad

	err := runWatch(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "load kubeconfig") {
		t.Fatalf("expected load-kubeconfig error, got %v", err)
	}
}
