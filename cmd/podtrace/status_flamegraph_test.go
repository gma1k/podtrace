package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/profiling"
)

func flamegraphOptions(output string) statusOptions {
	o := defaultStatusOptions()
	o.Output, o.Profile, o.SlowRequests = output, "shop/checkout", true
	return o
}

func TestStatusWritesTheWorkloadsFoldedStacks(t *testing.T) {
	f := newStatusFake()
	f.stacks = []byte("shop/checkout;main;price 3\n")
	useStatusFake(t, f)

	var out, progress bytes.Buffer
	if err := runStatus(context.Background(), flamegraphOptions("folded"), &out, &progress); err != nil {
		t.Fatal(err)
	}
	if out.String() != "shop/checkout;main;price 3\n" || progress.Len() != 0 {
		t.Errorf("out = %q, progress = %q", out.String(), progress.String())
	}
	if want := (profiling.StackSelection{Namespace: "shop", Workload: "checkout", SlowRequests: true}); f.stacksSel != want {
		t.Errorf("selection = %+v, want %+v", f.stacksSel, want)
	}
	if f.scrapes != 0 {
		t.Errorf("scraped %d times; a flame graph needs no metrics window", f.scrapes)
	}
}

func TestStatusSaysWhenNoAgentHasStacks(t *testing.T) {
	f := newStatusFake()
	useStatusFake(t, f)
	err := runStatus(context.Background(), flamegraphOptions("pprof"), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no agent has stacks for shop/checkout yet") {
		t.Errorf("err = %v", err)
	}
}

func TestAnAgentThatCannotServeStacksIsWarnedAbout(t *testing.T) {
	f := newStatusFake()
	f.stacksErr = errors.New("forbidden")
	useStatusFake(t, f)
	var progress bytes.Buffer
	err := runStatus(context.Background(), flamegraphOptions("folded"), &bytes.Buffer{}, &progress)
	if err == nil || !strings.Contains(progress.String(), "! no stacks from podtrace-agent-a on n1: forbidden") {
		t.Errorf("err = %v, progress = %q", err, progress.String())
	}
}
