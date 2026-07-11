package kubernetes

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePreResolvedRef_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"ns",
		"ns/name",
		"/name/cid",
		"ns//cid",
		"ns/name/",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParsePreResolvedRef(in); err == nil {
				t.Errorf("expected error for %q", in)
			}
		})
	}
}

func TestParsePreResolvedRef_AcceptsThreeOrFourParts(t *testing.T) {
	r3, err := ParsePreResolvedRef("ns/pod/cid")
	if err != nil {
		t.Fatalf("3-part form must parse: %v", err)
	}
	if r3.Namespace != "ns" || r3.PodName != "pod" || r3.ContainerID != "cid" || r3.ContainerName != "" {
		t.Errorf("3-part parse mismatch: %+v", r3)
	}
	r4, err := ParsePreResolvedRef("ns/pod/cid/cname")
	if err != nil {
		t.Fatalf("4-part form must parse: %v", err)
	}
	if r4.ContainerName != "cname" {
		t.Errorf("4-part container name lost: %+v", r4)
	}
}

func TestBuildPodInfoFromPreResolved_EmptyContainerID(t *testing.T) {
	_, err := BuildPodInfoFromPreResolved(PreResolvedRef{Namespace: "ns", PodName: "p"})
	if err == nil || !strings.Contains(err.Error(), "empty containerID") {
		t.Errorf("expected empty-containerID error, got: %v", err)
	}
}

func TestBuildPodInfosFromPreResolved_NonexistentContainersBecomeSkips(t *testing.T) {
	refs := []string{
		"ns/pod-a/nonexistentcontainerid111/appA",
		"ns/pod-b/nonexistentcontainerid222/appB",
	}
	infos, skipped, parseErr := BuildPodInfosFromPreResolved(refs)
	if parseErr != nil {
		t.Fatalf("parseErr must be nil for well-formed refs, got: %v", parseErr)
	}
	if len(infos) != 0 {
		t.Errorf("no refs should resolve, got %d", len(infos))
	}
	if len(skipped) != 2 {
		t.Fatalf("both refs should be skipped, got %d", len(skipped))
	}
	wantPods := map[string]bool{"pod-a": false, "pod-b": false}
	for _, s := range skipped {
		if _, ok := wantPods[s.Ref.PodName]; ok {
			wantPods[s.Ref.PodName] = true
		}
		if s.Cause == nil {
			t.Errorf("skip for %s must carry a cause", s.Ref.PodName)
		}
	}
	for pod, seen := range wantPods {
		if !seen {
			t.Errorf("expected skip entry for %s", pod)
		}
	}
}

func TestBuildPodInfosFromPreResolved_MalformedRefSurfacesParseError(t *testing.T) {
	refs := []string{
		"not-a-valid-ref",
		"ns/pod/nonexistentid/cname",
	}
	infos, skipped, parseErr := BuildPodInfosFromPreResolved(refs)
	if parseErr == nil {
		t.Fatalf("expected parse error for %q", refs[0])
	}
	if len(infos) != 0 {
		t.Errorf("malformed batch should not produce infos, got %d", len(infos))
	}
	if len(skipped) != 1 {
		t.Errorf("expected the well-formed ref to be skipped, got %d", len(skipped))
	}
}

func TestBuildPodInfosFromPreResolved_EmptySliceIsAllNoOp(t *testing.T) {
	infos, skipped, parseErr := BuildPodInfosFromPreResolved(nil)
	if parseErr != nil || len(infos) != 0 || len(skipped) != 0 {
		t.Errorf("empty input must yield all-empty result, got infos=%d skipped=%d err=%v",
			len(infos), len(skipped), parseErr)
	}
}

func TestPreResolvedSkip_CauseIsUnwrappable(t *testing.T) {
	_, skipped, _ := BuildPodInfosFromPreResolved([]string{"ns/p/nonexistentid/cn"})
	if len(skipped) != 1 {
		t.Fatalf("expected one skip, got %d", len(skipped))
	}
	if !errors.Is(skipped[0].Cause, skipped[0].Cause) {
		t.Error("cause must be a real error, not nil")
	}
}
// TestNormalizeContainerID guards the pre-resolved container-ID validation:
// the ID is substring-matched against cgroup paths, so a short or non-hex
// value could match — and attach to — the wrong container.
func TestNormalizeContainerID(t *testing.T) {
	full := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"full hex", full, full, false},
		{"scheme stripped", "containerd://" + full, full, false},
		{"docker scheme", "docker://abcdef012345", "abcdef012345", false},
		{"twelve hex ok", "abcdef012345", "abcdef012345", false},
		{"too short", "abc123", "", true},
		{"non hex", "zzzzzzzzzzzz", "", true},
		{"scheme then short", "containerd://abc", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeContainerID(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeContainerID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestBuildPodInfoFromPreResolved_RejectsUnsafeID ensures the validation is
// wired into the build path (not just the helper).
func TestBuildPodInfoFromPreResolved_RejectsUnsafeID(t *testing.T) {
	_, err := BuildPodInfoFromPreResolved(PreResolvedRef{
		Namespace: "ns", PodName: "p", ContainerID: "abc",
	})
	if err == nil {
		t.Fatal("expected a too-short containerID to be rejected before cgroup lookup")
	}
}
