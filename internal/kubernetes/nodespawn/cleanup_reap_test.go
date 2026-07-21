package nodespawn

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestDeletePod_WrapsNonNotFoundError(t *testing.T) {
	cs := fake.NewClientset(reapPod("stuck", "laptop", 1))
	cs.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver refused delete")
	})
	err := DeletePod(context.Background(), cs, "ns1", "stuck")
	if err == nil {
		t.Fatalf("expected wrapped error for non-NotFound delete failure")
	}
	if !strings.Contains(err.Error(), "delete ns1/stuck") {
		t.Errorf("error should identify the pod, got %q", err.Error())
	}
}

func TestReapStale_ListErrorPropagates(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	_, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "laptop", func(int) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "list stale pods") {
		t.Fatalf("expected list-stale-pods error, got %v", err)
	}
}

func TestReapStale_UsesRealProcessAliveCheck(t *testing.T) {
	cs := fake.NewClientset(
		reapPod("alive-owner", "", os.Getpid()),
		reapPod("dead-owner", "", 999999999),
	)
	n, err := ReapStale(context.Background(), cs, "ns1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("reaped = %d, want 1 (only the dead-owner pod)", n)
	}
	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), "alive-owner", metav1.GetOptions{}); gerr != nil {
		t.Errorf("pod owned by a live PID must be kept: %v", gerr)
	}
	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), "dead-owner", metav1.GetOptions{}); gerr == nil {
		t.Errorf("pod owned by a dead PID must be reaped")
	}
}

func TestPodOlderThan_AllBranches(t *testing.T) {
	const maxAge = time.Hour
	now := time.Now()

	cases := []struct {
		name      string
		createdAt string
		want      bool
	}{
		{"empty label", "", false},
		{"non-numeric", "not-a-number", false},
		{"zero seconds", "0", false},
		{"negative seconds", "-100", false},
		{"recent pod", strconv.FormatInt(now.Add(-time.Minute).Unix(), 10), false},
		{"old pod", strconv.FormatInt(now.Add(-2*time.Hour).Unix(), 10), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := podOlderThan(tc.createdAt, maxAge); got != tc.want {
				t.Errorf("podOlderThan(%q) = %v, want %v", tc.createdAt, got, tc.want)
			}
		})
	}
}

func TestProcessAlive_Init(t *testing.T) {
	if !processAlive(1) {
		t.Error("processAlive(1) must report init as alive (nil or EPERM, never ESRCH)")
	}
}
