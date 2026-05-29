package kubernetes

import (
	"fmt"
	"strings"
)

// PreResolvedRef is the workstation's hand-off to the spawn pod: enough fields
// to build PodInfo without making any Kubernetes API call.
type PreResolvedRef struct {
	Namespace     string
	PodName       string
	ContainerID   string
	ContainerName string
}

// ParsePreResolvedRef parses the "namespace/podName/containerID/containerName"
// form. Empty containerName is allowed (the spawned binary defaults to the
// first container's name during its own resolution).
func ParsePreResolvedRef(s string) (PreResolvedRef, error) {
	parts := strings.SplitN(s, "/", 4)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return PreResolvedRef{}, fmt.Errorf("preresolved ref %q must be ns/name/containerID[/containerName]", s)
	}
	ref := PreResolvedRef{
		Namespace:   parts[0],
		PodName:     parts[1],
		ContainerID: parts[2],
	}
	if len(parts) == 4 {
		ref.ContainerName = parts[3]
	}
	return ref, nil
}

// BuildPodInfoFromPreResolved finishes the workstation's hand-off by walking
// /sys/fs/cgroup (or whatever PODTRACE_CGROUP_BASE points at — inside the
// spawn pod that's /host/sys/fs/cgroup) to find the container's cgroup. No
// K8s API call, so no RBAC needed on the spawn pod's ServiceAccount.
func BuildPodInfoFromPreResolved(ref PreResolvedRef) (*PodInfo, error) {
	if ref.ContainerID == "" {
		return nil, fmt.Errorf("preresolved ref for %s/%s has empty containerID", ref.Namespace, ref.PodName)
	}
	cgroupPath, err := findCgroupPath(ref.ContainerID)
	if err != nil || cgroupPath == "" {
		fromProc, procErr := findCgroupPathFromProc(ref.ContainerID)
		if procErr != nil || fromProc == "" {
			return nil, NewCgroupNotFoundError(ref.ContainerID)
		}
		cgroupPath = fromProc
	}
	return &PodInfo{
		PodName:       ref.PodName,
		Namespace:     ref.Namespace,
		ContainerID:   ref.ContainerID,
		ContainerName: ref.ContainerName,
		CgroupPath:    cgroupPath,
		Labels:        map[string]string{},
	}, nil
}

// PreResolvedSkip records a single pre-resolved ref that couldn't be turned
// into a PodInfo on this node. The most common reason is a stale containerID
// (pod was rescheduled between workstation resolve time and spawn-pod start).
type PreResolvedSkip struct {
	Ref   PreResolvedRef
	Cause error
}

// BuildPodInfosFromPreResolved processes a list of "ns/name/containerID[/cName]"
// strings and returns:
//   - infos:    the successfully-resolved targets
//   - skipped:  per-ref failures with their reason (parse error, empty container,
//               cgroup not found on THIS node) — caller decides whether to warn
//               and continue, or hard-fail
//   - parseErr: the first malformed-input error, if any (returned alongside the
//               other slices so the caller can surface it deterministically)
func BuildPodInfosFromPreResolved(refs []string) (infos []*PodInfo, skipped []PreResolvedSkip, parseErr error) {
	for _, raw := range refs {
		ref, err := ParsePreResolvedRef(raw)
		if err != nil {
			if parseErr == nil {
				parseErr = err
			}
			continue
		}
		info, err := BuildPodInfoFromPreResolved(ref)
		if err != nil {
			skipped = append(skipped, PreResolvedSkip{Ref: ref, Cause: err})
			continue
		}
		infos = append(infos, info)
	}
	return infos, skipped, parseErr
}
