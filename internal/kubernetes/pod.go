package kubernetes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/cri"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/validation"
	"go.uber.org/zap"
)

// kubeletCgroupParent caches the value of kubelet's --cgroup-root or
// --cgroup-parent flag, detected once from /proc/<kubelet-pid>/cmdline.
var (
	kubeletCgroupParent     string
	kubeletCgroupParentOnce sync.Once
)

type PodResolver struct {
	clientset kubernetes.Interface
}

var _ PodResolverInterface = (*PodResolver)(nil)

func (r *PodResolver) GetClientset() kubernetes.Interface {
	return r.clientset
}

func NewPodResolver() (*PodResolver, error) {
	var config *rest.Config
	var err error

	config, err = rest.InClusterConfig()
	if err != nil {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

		if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
			loadingRules.ExplicitPath = kubeconfig
		} else {
			sudoUser := os.Getenv("SUDO_USER")
			if sudoUser != "" {
				homePath := filepath.Join("/home", sudoUser, ".kube", "config")
				if _, err := os.Stat(homePath); err == nil {
					loadingRules.ExplicitPath = homePath
				}
			}
			if loadingRules.ExplicitPath == "" {
				if home := os.Getenv("HOME"); home != "" && home != "/root" {
					homePath := filepath.Join(home, ".kube", "config")
					if _, err := os.Stat(homePath); err == nil {
						loadingRules.ExplicitPath = homePath
					}
				}
			}
		}

		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		config, err = kubeConfig.ClientConfig()
		if err != nil {
			return nil, NewKubeconfigError(err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, NewClientsetError(err)
	}

	return &PodResolver{clientset: clientset}, nil
}

func (r *PodResolver) ResolvePod(ctx context.Context, podName, namespace, containerName string) (*PodInfo, error) {
	pod, err := r.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, NewPodNotFoundError(podName, namespace, err)
	}

	if len(pod.Status.ContainerStatuses) == 0 {
		return nil, NewNoContainersError()
	}

	var containerStatus *corev1.ContainerStatus
	var containerSpec *corev1.Container

	if containerName != "" {
		for i, status := range pod.Status.ContainerStatuses {
			if status.Name == containerName {
				containerStatus = &pod.Status.ContainerStatuses[i]
				for j, spec := range pod.Spec.Containers {
					if spec.Name == containerName {
						containerSpec = &pod.Spec.Containers[j]
						break
					}
				}
				break
			}
		}
		if containerStatus == nil {
			return nil, NewContainerNotFoundError(containerName)
		}
	} else {
		containerStatus = &pod.Status.ContainerStatuses[0]
		containerSpec = &pod.Spec.Containers[0]
	}

	containerID := containerStatus.ContainerID

	parts := strings.Split(containerID, "://")
	if len(parts) != 2 {
		return nil, NewInvalidContainerIDError("invalid container ID format")
	}
	shortID := parts[1]

	if !validation.ValidateContainerID(shortID) {
		return nil, NewInvalidContainerIDError("validation failed")
	}

	cgroupPath, err := resolveCgroupPathCRI(ctx, shortID)
	if err != nil || cgroupPath == "" {
		logger.Debug("CRI cgroup resolution failed, trying filesystem scan", zap.Error(err), zap.String("container_id", shortID))
		cgroupPath, err = findCgroupPath(shortID)
		if err != nil {
			logger.Debug("Filesystem cgroup scan failed, trying /proc fallback", zap.Error(err), zap.String("container_id", shortID))
			cgroupPathFromProc, procErr := findCgroupPathFromProc(shortID)
			if procErr == nil && cgroupPathFromProc != "" {
				cgroupPath = cgroupPathFromProc
				logger.Debug("Found cgroup path via /proc fallback", zap.String("cgroup_path", cgroupPath))
			} else {
				return nil, NewCgroupNotFoundError(shortID)
			}
		} else {
			logger.Debug("Found cgroup path via filesystem scan", zap.String("cgroup_path", cgroupPath))
		}
	} else {
		logger.Debug("Found cgroup path via CRI", zap.String("cgroup_path", cgroupPath))
	}

	labels := make(map[string]string)
	if pod.Labels != nil {
		for k, v := range pod.Labels {
			labels[k] = v
		}
	}

	var ownerKind, ownerName string
	if len(pod.OwnerReferences) > 0 {
		ownerKind = pod.OwnerReferences[0].Kind
		ownerName = pod.OwnerReferences[0].Name
	}

	return &PodInfo{
		PodName:       podName,
		Namespace:     namespace,
		ContainerID:   shortID,
		CgroupPath:    cgroupPath,
		ContainerName: containerSpec.Name,
		Labels:        labels,
		PodIP:         pod.Status.PodIP,
		OwnerKind:     ownerKind,
		OwnerName:     ownerName,
	}, nil
}

// cgroupRootCandidates returns base paths to search when resolving cgroup paths.
// It covers:
//   - The configured cgroup base (default /sys/fs/cgroup)
//   - The systemd sub-hierarchy (cgroup v1 with systemd driver)
//   - A custom cgroup-root/cgroup-parent set via kubelet flags (GKE, AKS, EKS)
func cgroupRootCandidates() []string {
	base := config.CgroupBasePath
	seen := map[string]bool{base: true}
	candidates := []string{base}

	// cgroup v1 systemd hierarchy.
	if systemdRoot := filepath.Join(base, "systemd"); dirExists(systemdRoot) {
		if !seen[systemdRoot] {
			seen[systemdRoot] = true
			candidates = append(candidates, systemdRoot)
		}
	}

	// Kubelet --cgroup-root / --cgroup-parent (GKE, AKS, EKS, custom clusters).
	if kcp := detectKubeletCgroupParent(); kcp != "" {
		// kcp may be a relative path like "kubepods" or absolute.
		var full string
		if filepath.IsAbs(kcp) {
			full = kcp
		} else {
			full = filepath.Join(base, kcp)
		}
		if dirExists(full) && !seen[full] {
			seen[full] = true
			candidates = append(candidates, full)
		}
	}

	return candidates
}

// detectKubeletCgroupParent finds the value of --cgroup-root or --cgroup-parent
// from the running kubelet process's command line. The result is cached.
func detectKubeletCgroupParent() string {
	kubeletCgroupParentOnce.Do(func() {
		kubeletCgroupParent = readKubeletCgroupFlag()
	})
	return kubeletCgroupParent
}

// readKubeletCgroupFlag reads /proc and finds the kubelet cmdline.
func readKubeletCgroupFlag() string {
	procPath := config.ProcBasePath
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if pid == "" || pid[0] < '1' || pid[0] > '9' {
			continue
		}

		commPath := filepath.Join(procPath, pid, "comm")
		comm, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) != "kubelet" {
			continue
		}

		cmdlinePath := filepath.Join(procPath, pid, "cmdline")
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		// cmdline is NUL-separated.
		args := strings.Split(string(data), "\x00")
		for i, arg := range args {
			for _, flag := range []string{"--cgroup-root", "--cgroup-parent"} {
				if arg == flag && i+1 < len(args) {
					v := strings.TrimSpace(args[i+1])
					if v != "" {
						logger.Debug("Detected kubelet cgroup flag",
							zap.String("flag", flag), zap.String("value", v))
						return v
					}
				}
				if strings.HasPrefix(arg, flag+"=") {
					v := strings.TrimPrefix(arg, flag+"=")
					v = strings.TrimSpace(v)
					if v != "" {
						logger.Debug("Detected kubelet cgroup flag",
							zap.String("flag", flag), zap.String("value", v))
						return v
					}
				}
			}
		}
		// Found kubelet but no relevant flag — stop searching.
		break
	}
	return ""
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func resolveCgroupPathCRI(ctx context.Context, containerID string) (string, error) {
	if os.Getenv("PODTRACE_CRI_RESOLVE") == "false" {
		return "", errors.New("podtrace: CRI resolution disabled")
	}
	r, err := cri.NewResolver()
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()

	info, err := r.ResolveContainer(ctx, containerID)
	if err != nil {
		return "", err
	}
	if info == nil || info.CgroupsPath == "" {
		return "", errors.New("podtrace: CRI returned no cgroups path")
	}

	cg := info.CgroupsPath
	if !strings.HasPrefix(cg, "/") {
		cg = "/" + cg
	}
	if cg == "/" {
		return "", errors.New("podtrace: CRI returned root cgroups path")
	}
	trimmed := strings.TrimPrefix(cg, "/")

	for _, root := range cgroupRootCandidates() {
		fullPath := filepath.Join(root, trimmed)
		if fullPath == root {
			continue
		}
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath, nil
		}
	}
	if _, err := os.Stat(cg); err == nil {
		if cg != config.CgroupBasePath && cg != filepath.Join(config.CgroupBasePath, "systemd") {
			return cg, nil
		}
	}
	return "", errors.New("podtrace: CRI cgroup path not found on filesystem")
}

type PodInfo struct {
	PodName       string
	Namespace     string
	ContainerID   string
	CgroupPath    string
	ContainerName string
	Labels        map[string]string
	PodIP         string
	OwnerKind     string
	OwnerName     string
}

func findCgroupPath(containerID string) (string, error) {
	isV2, _ := isCgroupV2(config.CgroupBasePath)

	if isV2 {
		return findCgroupPathV2(containerID)
	}

	return findCgroupPathV1(containerID)
}

func isCgroupV2(basePath string) (bool, error) {
	controllersPath := filepath.Join(basePath, "cgroup.controllers")
	if _, err := os.Stat(controllersPath); err == nil {
		return true, nil
	}
	return false, nil
}

func findCgroupPathV2(containerID string) (string, error) {
	var basePaths []string
	for _, root := range cgroupRootCandidates() {
		basePaths = append(basePaths,
			filepath.Join(root, "kubepods"),
			filepath.Join(root, "kubepods.slice"),
			filepath.Join(root, "kubepods-burstable"),
			filepath.Join(root, "kubepods-burstable.slice"),
			filepath.Join(root, "kubepods-besteffort"),
			filepath.Join(root, "kubepods-besteffort.slice"),
			filepath.Join(root, "system"),
			filepath.Join(root, "system.slice"),
			filepath.Join(root, "user"),
			filepath.Join(root, "user.slice"),
			root,
		)
	}

	var errFound = errors.New("podtrace: cgroup found")
	shortID := containerID
	if len(containerID) >= 12 {
		shortID = containerID[:12]
	}

	for _, basePath := range basePaths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		var foundPath string
		found := false
		_ = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				return nil
			}
			baseName := filepath.Base(path)
			pathStr := path
			if strings.Contains(pathStr, containerID) || strings.Contains(pathStr, shortID) || strings.Contains(baseName, containerID) || strings.Contains(baseName, shortID) {
				cgroupProcsPath := filepath.Join(path, "cgroup.procs")
				if _, err := os.Stat(cgroupProcsPath); err == nil {
					foundPath = path
					found = true
					return errFound
				}
			}
			return nil
		})

		if found && foundPath != "" {
			return foundPath, nil
		}
	}

	return "", NewCgroupNotFoundError(containerID)
}

func findCgroupPathV1(containerID string) (string, error) {
	var paths []string
	for _, root := range cgroupRootCandidates() {
		paths = append(paths,
			filepath.Join(root, "kubepods.slice"),
			filepath.Join(root, "system.slice"),
			filepath.Join(root, "user.slice"),
		)
	}

	var errFound = errors.New("podtrace: cgroup found")
	shortID := containerID
	if len(containerID) >= 12 {
		shortID = containerID[:12]
	}

	for _, basePath := range paths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		var foundPath string
		found := false
		_ = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.Contains(path, containerID) || strings.Contains(path, shortID) {
				foundPath = path
				found = true
				return errFound
			}
			return nil
		})

		if found && foundPath != "" {
			return foundPath, nil
		}
	}

	return "", NewCgroupNotFoundError(containerID)
}

func findCgroupPathFromProc(containerID string) (string, error) {
	procPath := config.ProcBasePath
	shortID := containerID
	if len(containerID) >= 12 {
		shortID = containerID[:12]
	}

	entries, err := os.ReadDir(procPath)
	if err != nil {
		return "", NewCgroupNotFoundError(containerID)
	}

	var foundPath string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		cgroupFile := filepath.Join(procPath, pidStr, "cgroup")
		data, err := os.ReadFile(cgroupFile)
		if err != nil {
			continue
		}

		cgroupContent := string(data)
		if !strings.Contains(cgroupContent, containerID) && !strings.Contains(cgroupContent, shortID) {
			continue
		}

		lines := strings.Split(cgroupContent, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "0::") {
				cgroupPath := strings.TrimPrefix(line, "0::")
				if cgroupPath == "" || cgroupPath == "/" {
					for _, root := range cgroupRootCandidates() {
						fullPath := root
						if _, err := os.Stat(fullPath); err == nil {
							if _, err := os.Stat(filepath.Join(fullPath, "cgroup.procs")); err == nil {
								foundPath = fullPath
								break
							}
						}
					}
				} else {
					for _, root := range cgroupRootCandidates() {
						fullPath := filepath.Join(root, strings.TrimPrefix(cgroupPath, "/"))
						if _, err := os.Stat(fullPath); err == nil {
							if _, err := os.Stat(filepath.Join(fullPath, "cgroup.procs")); err == nil {
								foundPath = fullPath
								break
							}
						}
					}
				}
			} else {
				parts := strings.Split(line, ":")
				if len(parts) >= 3 {
					cgroupPath := parts[2]
					if cgroupPath != "" && cgroupPath != "/" {
						for _, root := range cgroupRootCandidates() {
							fullPath := filepath.Join(root, strings.TrimPrefix(cgroupPath, "/"))
							if _, err := os.Stat(fullPath); err == nil {
								foundPath = fullPath
								break
							}
						}
					}
				}
			}
			if foundPath != "" {
				break
			}
		}

		if foundPath != "" {
			break
		}
	}

	if foundPath != "" {
		return foundPath, nil
	}

	return "", NewCgroupNotFoundError(containerID)
}
