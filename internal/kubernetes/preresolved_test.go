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