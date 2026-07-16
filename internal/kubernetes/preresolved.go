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
// form. Each ref names exactly one container; a multi-container pod arrives
// as one ref per container. Empty containerName is allowed.
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
// /sys/fs/cgroup to find the container's cgroup.
func BuildPodInfoFromPreResolved(ref PreResolvedRef) (*PodInfo, error) {
	if ref.ContainerID == "" {
		return nil, fmt.Errorf("preresolved ref for %s/%s has empty containerID", ref.Namespace, ref.PodName)
	}
	normalizedID, err := normalizeContainerID(ref.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("preresolved ref for %s/%s: %w", ref.Namespace, ref.PodName, err)
	}
	ref.ContainerID = normalizedID
	cgroupPath, err := findCgroupPath(ref.ContainerID)
	if err != nil || cgroupPath == "" {
		fromProc, procErr := findCgroupPathFromProc(ref.ContainerID)
		if procErr != nil || fromProc == "" {
			return nil, NewCgroupNotFoundError(ref.ContainerID)
		}
		cgroupPath = fromProc
	}
	return &PodInfo{
		PodName:   ref.PodName,
		Namespace: ref.Namespace,
		Containers: []ContainerTarget{
			{Name: ref.ContainerName, ID: ref.ContainerID, CgroupPath: cgroupPath},
		},
		ContainerID:   ref.ContainerID,
		ContainerName: ref.ContainerName,
		CgroupPath:    cgroupPath,
		Labels:        map[string]string{},
	}, nil
}

const minContainerIDLen = 12

// normalizeContainerID strips an optional runtime scheme ("containerd://",
// "docker://", "cri-o://") and validates the remainder is a plausible
// container ID: hexadecimal and at least minContainerIDLen chars long.
func normalizeContainerID(id string) (string, error) {
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	if len(id) < minContainerIDLen {
		return "", fmt.Errorf("container id %q too short (need >= %d hex chars) to safely match a cgroup", id, minContainerIDLen)
	}
	for _, c := range id {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return "", fmt.Errorf("container id %q is not hexadecimal", id)
		}
	}
	return id, nil
}

// PreResolvedSkip records a single pre-resolved ref that couldn't be turned
// into a PodInfo on this node.
type PreResolvedSkip struct {
	Ref   PreResolvedRef
	Cause error
}

// BuildPodInfosFromPreResolved processes a list of "ns/name/containerID[/cName]"
// strings and returns:
//   - infos:    the successfully-resolved targets
//   - skipped:  per-ref failures with their reason (parse error, empty container,
//     cgroup not found on THIS node) — caller decides whether to warn
//     and continue, or hard-fail
//   - parseErr: the first malformed-input error, if any (returned alongside the
//     other slices so the caller can surface it deterministically)
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
