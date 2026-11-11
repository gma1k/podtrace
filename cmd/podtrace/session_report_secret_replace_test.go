package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/util/wait"
	k8stesting "k8s.io/client-go/testing"
)

func fastReplaceCreateBackoff(t *testing.T) {
	t.Helper()
	orig := replaceCreateBackoff
	replaceCreateBackoff = wait.Backoff{Steps: 4, Duration: time.Millisecond}
	t.Cleanup(func() { replaceCreateBackoff = orig })
}

func failCreates(client *k8stesting.Fake, times int, fail error) *int {
	creates := 0
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		if creates <= times {
			return true, nil, fail
		}
		return false, nil, nil
	})
	return &creates
}

func TestReplaceReportSecretRetriesATransientCreateFailure(t *testing.T) {
	fastReplaceCreateBackoff(t)
	client := forbiddenUpdateClient()
	creates := failCreates(&client.Fake, 2, apierrors.NewServerTimeout(schema.GroupResource{Resource: "secrets"}, "create", 1))

	if err := upsertReportSecret(context.Background(), client, "podtrace-system", "staging", "report-n1.txt", "body"); err != nil {
		t.Fatalf("a transient create failure after the delete lost the report: %v", err)
	}
	got, err := client.CoreV1().Secrets("podtrace-system").Get(context.Background(), "staging", metav1.GetOptions{})
	if err != nil || string(got.Data["report-n1.txt"]) != "body" {
		t.Fatalf("staging Secret after retry = %+v, %v", got, err)
	}
	if *creates != 3 {
		t.Errorf("creates = %d, want 3", *creates)
	}
}

func TestReplaceReportSecretDoesNotRetryAPermanentCreateFailure(t *testing.T) {
	fastReplaceCreateBackoff(t)
	client := forbiddenUpdateClient()
	invalid := apierrors.NewInvalid(schema.GroupKind{Kind: "Secret"}, "staging", field.ErrorList{field.Invalid(field.NewPath("data"), "", "rejected")})
	creates := failCreates(&client.Fake, 10, invalid)

	err := upsertReportSecret(context.Background(), client, "podtrace-system", "staging", "report-n1.txt", "body")

	if err == nil || !strings.Contains(err.Error(), "staged reports in it are lost") {
		t.Fatalf("upsertReportSecret = %v, want the loss reported", err)
	}
	if *creates != 1 {
		t.Errorf("creates = %d, want a permanent failure tried once", *creates)
	}
}

func TestReplaceReportSecretStopsRetryingWhenTheContextEnds(t *testing.T) {
	fastReplaceCreateBackoff(t)
	client := forbiddenUpdateClient()
	ctx, cancel := context.WithCancel(context.Background())
	creates := 0
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		cancel()
		return true, nil, errors.New("connection reset")
	})

	if err := upsertReportSecret(ctx, client, "podtrace-system", "staging", "report-n1.txt", "body"); err == nil {
		t.Fatal("upsertReportSecret succeeded although every create failed")
	}
	if creates != 1 {
		t.Errorf("creates = %d, want no retry after the context ended", creates)
	}
}

func TestRetriableCreateError(t *testing.T) {
	gr := schema.GroupResource{Resource: "secrets"}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"already exists", apierrors.NewAlreadyExists(gr, "s"), false},
		{"forbidden", apierrors.NewForbidden(gr, "s", errors.New("no")), false},
		{"unauthorized", apierrors.NewUnauthorized("no"), false},
		{"bad request", apierrors.NewBadRequest("no"), false},
		{"namespace gone", apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "ns"), false},
		{"method not supported", apierrors.NewMethodNotSupported(gr, "create"), false},
		{"too large", apierrors.NewRequestEntityTooLargeError("big"), false},
		{"server timeout", apierrors.NewServerTimeout(gr, "create", 1), true},
		{"too many requests", apierrors.NewTooManyRequests("slow down", 1), true},
		{"internal", apierrors.NewInternalError(errors.New("etcd")), true},
		{"network", errors.New("connection reset by peer"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retriableCreateError(tt.err); got != tt.want {
				t.Errorf("retriableCreateError = %v, want %v", got, tt.want)
			}
		})
	}
}
