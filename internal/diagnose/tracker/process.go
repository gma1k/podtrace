package tracker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/procfs"
	"github.com/podtrace/podtrace/internal/validation"
)

type PidInfo struct {
	Pid        uint32
	Name       string
	Count      int
	Percentage float64
	Pod        string
}

func (p PidInfo) PodSuffix() string {
	if p.Pod == "" {
		return ""
	}
	return " [pod: " + p.Pod + "]"
}

func AnalyzeProcessActivity(events []*events.Event) []PidInfo {
	pidMap := make(map[uint32]int)
	totalEvents := len(events)

	pidPod := make(map[uint32]string)

	for _, e := range events {
		if e == nil {
			continue
		}
		pidMap[e.PID]++
		if e.K8s != nil && e.K8s.PodName != "" {
			if _, ok := pidPod[e.PID]; !ok {
				pidPod[e.PID] = e.K8s.PodName
			}
		}
	}

	type latestName struct {
		ts   uint64
		name string
	}
	latest := make(map[uint32]latestName)
	transient := make(map[uint32]latestName)
	for _, e := range events {
		if e == nil || e.ProcessName == "" {
			continue
		}
		bucket := latest
		if isTransientName(e.ProcessName) {
			bucket = transient
		}
		if cur, ok := bucket[e.PID]; !ok || e.Timestamp > cur.ts {
			bucket[e.PID] = latestName{ts: e.Timestamp, name: e.ProcessName}
		}
	}

	var pidInfos []PidInfo
	for pid, count := range pidMap {
		percentage := float64(count) / float64(totalEvents) * 100
		name := ""
		if l, ok := latest[pid]; ok {
			name = l.name
		} else if l, ok := transient[pid]; ok {
			name = l.name
		}
		if name == "" {
			name = getProcessName(pid)
		}
		if name == "" {
			name = "unknown"
		}
		pidInfos = append(pidInfos, PidInfo{
			Pid:        pid,
			Name:       name,
			Count:      count,
			Percentage: percentage,
			Pod:        pidPod[pid],
		})
	}

	sort.Slice(pidInfos, func(i, j int) bool {
		return pidInfos[i].Count > pidInfos[j].Count
	})

	return pidInfos
}

// isTransientName flags comm values that the kernel sets briefly during
// container setup — they get superseded by the user's command after runc's
// setns+exec dance. Aggregation prefers a stable name over these whenever
// the same PID also has events tagged with the post-exec identity.
func isTransientName(name string) bool {
	if strings.HasPrefix(name, "runc-bootstrap[") {
		return true
	}
	if strings.HasPrefix(name, "runc:[") {
		return true
	}
	return false
}

func getProcessName(pid uint32) string {
	name := getProcessNameFromProc(pid)
	return validation.SanitizeProcessName(name)
}

func getProcessNameFromProc(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	pidStr := fmt.Sprintf("%d", pid)
	name := ""

	if data, err := procfs.ReadFile(pidStr + "/stat"); err == nil {
		statStr := string(data)
		start := strings.Index(statStr, "(")
		end := strings.LastIndex(statStr, ")")
		if start >= 0 && end > start {
			name = statStr[start+1 : end]
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/comm"); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	if name == "" {
		if cmdline, err := procfs.ReadFile(pidStr + "/cmdline"); err == nil {
			parts := strings.Split(string(cmdline), "\x00")
			if len(parts) > 0 && parts[0] != "" {
				name = parts[0]
				if idx := strings.LastIndex(name, "/"); idx >= 0 {
					name = name[idx+1:]
				}
			}
		}
	}

	if name == "" {
		if link, err := procfs.Readlink(pidStr + "/exe"); err == nil {
			if idx := strings.LastIndex(link, "/"); idx >= 0 {
				name = link[idx+1:]
			} else {
				name = link
			}
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/status"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "Name:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						name = parts[1]
						break
					}
				}
			}
		}
	}

	return name
}
