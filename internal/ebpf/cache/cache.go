package cache

import (
	"fmt"
	"strings"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/procfs"
	"github.com/podtrace/podtrace/internal/validation"
)

var (
	globalCache *LRUCache
)

func init() {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	globalCache = NewLRUCache(config.CacheMaxSize, ttl)
}

func ResetGlobalCache() {
	if globalCache != nil {
		globalCache.Close()
	}
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	globalCache = NewLRUCache(config.CacheMaxSize, ttl)
}

func GetProcessNameQuick(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	SnapshotCPUTime(pid)

	if name, ok := globalCache.Get(pid); ok {
		return name
	}

	metricsexporter.RecordProcessCacheMiss()

	name := ""

	pidStr := fmt.Sprintf("%d", pid)

	if cmdline, err := procfs.ReadFile(pidStr + "/cmdline"); err == nil {
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			name = parts[0]
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/stat"); err == nil {
			statStr := string(data)
			start := strings.Index(statStr, "(")
			end := strings.LastIndex(statStr, ")")
			if start >= 0 && end > start {
				name = statStr[start+1 : end]
			}
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/comm"); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	sanitized := validation.SanitizeProcessName(name)
	globalCache.Set(pid, sanitized)
	return sanitized
}
