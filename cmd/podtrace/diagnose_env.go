package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/cri"
	"github.com/gma1k/podtrace/internal/ebpf/embedded"
	"github.com/gma1k/podtrace/internal/ebpf/loader"
)

type envReport struct {
	Time           string   `json:"time"`
	GoVersion      string   `json:"goVersion"`
	GOOS           string   `json:"goos"`
	GOARCH         string   `json:"goarch"`
	KernelRelease  string   `json:"kernelRelease"`
	CgroupBase     string   `json:"cgroupBase"`
	ProcBase       string   `json:"procBase"`
	CgroupV2       bool     `json:"cgroupV2"`
	BTFVmlinux     bool     `json:"btfVmlinuxPresent"`
	BTFFile        string   `json:"btfFile"`
	CRIEndpointEnv string   `json:"criEndpointEnv"`
	CRICandidates  []string `json:"criCandidates"`
	CRIDetected    string   `json:"criDetected"`
	BPFObjectPath  string   `json:"bpfObjectPath"`
	BPFEmbedded    bool     `json:"bpfEmbeddedAvailable"`
	BPFPrograms    []string `json:"bpfPrograms"`
	BPFMaps        []string `json:"bpfMaps"`
	HasCgroupIDMap bool     `json:"hasTargetCgroupIdMap"`
	Warnings       []string `json:"warnings"`
}

func newDiagnoseEnvCmd() *cobra.Command {
	var dumpBPFObject string

	cmd := &cobra.Command{
		Use:   "diagnose-env",
		Short: "Print environment diagnostics for Podtrace (kernel/BTF/cgroups/CRI/BPF)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dumpBPFObject != "" {
				return writeEmbeddedBPFObject(dumpBPFObject)
			}
			rep := collectEnvReport()
			out, _ := json.MarshalIndent(rep, "", "  ")
			fmt.Println(string(out))
			return nil
		},
	}
	cmd.Flags().StringVar(&dumpBPFObject, "dump-bpf-object", "",
		"Write the embedded BPF object to this path and exit. Needed to minimise a BTF "+
			"blob for btfMode=file: bpftool gen min_core_btf takes the object podtrace "+
			"will actually load, and it is embedded in this binary rather than shipped "+
			"as a file.")
	return cmd
}

// writeEmbeddedBPFObject writes the BPF object compiled into this binary so it
// can be passed to "bpftool gen min_core_btf".
func writeEmbeddedBPFObject(path string) error {
	return writeBPFObject(path, embedded.EmbeddedPodtraceBPFObj)
}

// writeBPFObject takes the bytes rather than reading the embedded variable so
// the branches stay reachable in a test build, where the embed_bpf tag is off
// and the embedded object is empty.
func writeBPFObject(path string, obj []byte) error {
	if len(obj) == 0 {
		return fmt.Errorf("this build embeds no BPF object (built without the embed_bpf tag), so there is nothing to write; use the object from a release build or from internal/ebpf/embedded in the source tree")
	}
	if err := os.WriteFile(path, obj, 0o600); err != nil {
		return fmt.Errorf("write BPF object to %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(obj), path)
	return nil
}

func collectEnvReport() envReport {
	rep := envReport{
		Time:           time.Now().Format(time.RFC3339),
		GoVersion:      runtime.Version(),
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		CgroupBase:     config.CgroupBasePath,
		ProcBase:       config.ProcBasePath,
		BTFFile:        config.BTFFilePath,
		CRIEndpointEnv: os.Getenv("PODTRACE_CRI_ENDPOINT"),
		CRICandidates:  cri.DefaultCandidateEndpoints(),
		BPFObjectPath:  config.BPFObjectPath,
		BPFEmbedded:    len(embedded.EmbeddedPodtraceBPFObj) > 0,
	}

	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		rep.KernelRelease = bytesToString(u.Release[:])
	}

	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		rep.CgroupV2 = true
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		rep.BTFVmlinux = true
	}

	if r, err := cri.NewResolver(); err == nil {
		rep.CRIDetected = r.Endpoint()
		_ = r.Close()
	}

	if spec, err := loader.LoadPodtrace(); err == nil && spec != nil {
		for name := range spec.Programs {
			rep.BPFPrograms = append(rep.BPFPrograms, name)
		}
		for name := range spec.Maps {
			rep.BPFMaps = append(rep.BPFMaps, name)
			if name == "target_cgroup_ids" {
				rep.HasCgroupIDMap = true
			}
		}
	} else if err != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("failed to load BPF spec: %v", err))
	}

	if !rep.BTFVmlinux && rep.BTFFile == "" {
		rep.Warnings = append(rep.Warnings, "kernel BTF (/sys/kernel/btf/vmlinux) not found and PODTRACE_BTF_FILE not set; CO-RE relocations may fail")
	}
	if rep.CgroupV2 && !rep.HasCgroupIDMap {
		rep.Warnings = append(rep.Warnings, "cgroup v2 detected but BPF map target_cgroup_ids missing; kernel-side cgroup filtering will be unavailable")
	}

	return rep
}

func bytesToString(bts []byte) string {
	var b bytes.Buffer
	for _, c := range bts {
		if c == 0 {
			break
		}
		b.WriteByte(c)
	}
	return b.String()
}
