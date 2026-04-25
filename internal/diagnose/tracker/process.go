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
}

func AnalyzeProcessActivity(events []*events.Event) []PidInfo {
	pidMap := make(map[uint32]int)
	totalEvents := len(events)

	for _, e := range events {
		pidMap[e.PID]++
	}

	var pidInfos []PidInfo
	for pid, count := range pidMap {
		percentage := float64(count) / float64(totalEvents) * 100
		name := ""
		for _, e := range events {
			if e.PID == pid && e.ProcessName != "" {
				name = e.ProcessName
				break
			}
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
		})
	}

	sort.Slice(pidInfos, func(i, j int) bool {
		return pidInfos[i].Count > pidInfos[j].Count
	})

	return pidInfos
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
