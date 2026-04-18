package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestBytesToString_Normal(t *testing.T) {
	input := []byte{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'}
	got := bytesToString(input)
	if got != "hello" {
		t.Errorf("expected %q, got %q", "hello", got)
	}
}

func TestBytesToString_NoNull(t *testing.T) {
	input := []byte{'a', 'b', 'c'}
	got := bytesToString(input)
	if got != "abc" {
		t.Errorf("expected %q, got %q", "abc", got)
	}
}

func TestBytesToString_Empty(t *testing.T) {
	got := bytesToString([]byte{})
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestBytesToString_AllZero(t *testing.T) {
	got := bytesToString([]byte{0, 0, 0})
	if got != "" {
		t.Errorf("expected empty string for all-zero input, got %q", got)
	}
}

func TestBytesToString_LeadingNull(t *testing.T) {
	got := bytesToString([]byte{0, 'a', 'b'})
	if got != "" {
		t.Errorf("expected empty string when first byte is null, got %q", got)
	}
}

func TestCollectEnvReport_Fields(t *testing.T) {
	rep := collectEnvReport()

	if rep.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}
	if rep.GOOS == "" {
		t.Error("GOOS should not be empty")
	}
	if rep.GOARCH == "" {
		t.Error("GOARCH should not be empty")
	}
	if rep.Time == "" {
		t.Error("Time should not be empty")
	}
}

func TestCollectEnvReport_CRICandidates(t *testing.T) {
	rep := collectEnvReport()
	if len(rep.CRICandidates) == 0 {
		t.Error("CRICandidates should not be empty")
	}
}

func TestCollectEnvReport_BTFWarning(t *testing.T) {
	rep := collectEnvReport()
	// If BTFVmlinux is false and BTFFile is empty, there should be a warning.
	if !rep.BTFVmlinux && rep.BTFFile == "" {
		hasWarning := false
		for _, w := range rep.Warnings {
			if strings.Contains(w, "BTF") {
				hasWarning = true
				break
			}
		}
		if !hasWarning {
			t.Error("expected BTF warning when BTF not available")
		}
	}
}

func TestNewDiagnoseEnvCmd(t *testing.T) {
	cmd := newDiagnoseEnvCmd()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd.Use != "diagnose-env" {
		t.Errorf("expected Use=%q, got %q", "diagnose-env", cmd.Use)
	}
	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}
}

func TestMockTracer_AllMethods(t *testing.T) {
	m := &mockTracer{}

	// All default implementations should return nil.
	if err := m.AttachToCgroup("/some/path"); err != nil {
		t.Errorf("AttachToCgroup: %v", err)
	}
	if err := m.SetContainerID("abc"); err != nil {
		t.Errorf("SetContainerID: %v", err)
	}
	ch := make(chan interface{}, 1)
	_ = ch
	if err := m.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestMockTracer_CustomFunctions(t *testing.T) {
	called := map[string]bool{}
	m := &mockTracer{
		attachToCgroupFunc: func(p string) error {
			called["attach"] = true
			return nil
		},
		setContainerIDFunc: func(id string) error {
			called["setID"] = true
			return nil
		},
		stopFunc: func() error {
			called["stop"] = true
			return nil
		},
	}

	_ = m.AttachToCgroup("/path")
	_ = m.SetContainerID("id")
	_ = m.Stop()

	for _, k := range []string{"attach", "setID", "stop"} {
		if !called[k] {
			t.Errorf("expected %s to be called", k)
		}
	}
}

func TestMockPodResolver_Default(t *testing.T) {
	m := &mockPodResolver{}
	info, err := m.ResolvePod(context.TODO(), "mypod", "default", "mycontainer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil PodInfo")
	}
	if info.PodName != "mypod" {
		t.Errorf("expected PodName=mypod, got %q", info.PodName)
	}
	if info.Namespace != "default" {
		t.Errorf("expected Namespace=default, got %q", info.Namespace)
	}
}

func TestMockPodResolver_CustomFunc(t *testing.T) {
	m := &mockPodResolver{}
	// nil resolvePodFunc → default implementation
	info, err := m.ResolvePod(context.TODO(), "pod2", "ns2", "container2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil default info")
	}
	if info.ContainerName != "container2" {
		t.Errorf("expected ContainerName=container2, got %q", info.ContainerName)
	}
}

func TestMockTracer_Start_DefaultFunc(t *testing.T) {
	ctx := t.Context()
	m := &mockTracer{}
	ch := make(chan *events.Event, 1)
	if err := m.Start(ctx, ch); err != nil {
		t.Errorf("Start with nil startFunc should return nil, got %v", err)
	}
}

func TestMockTracer_Start_CustomFunc(t *testing.T) {
	ctx := t.Context()
	called := false
	m := &mockTracer{
		startFunc: func(c context.Context, ch chan<- *events.Event) error {
			called = true
			return nil
		},
	}
	ch := make(chan *events.Event, 1)
	if err := m.Start(ctx, ch); err != nil {
		t.Errorf("Start returned unexpected error: %v", err)
	}
	if !called {
		t.Error("expected startFunc to be called")
	}
}

// TestNewDiagnoseEnvCmd_Execute runs the command's RunE to cover the closure.
func TestNewDiagnoseEnvCmd_Execute(t *testing.T) {
	cmd := newDiagnoseEnvCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	// Execute the command; it should succeed (prints JSON to stdout).
	if err := cmd.Execute(); err != nil {
		t.Errorf("Execute() returned unexpected error: %v", err)
	}
}
