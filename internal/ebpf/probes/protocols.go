package probes

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
)

// attachUprobeSymbols attaches uprobe+uretprobe pairs for the given symbols
// on the given executable path. Failures are logged but not fatal.
func attachUprobeSymbols(exe *link.Executable, coll *ebpf.Collection, libPath string,
	pairs []struct{ uprobe, uretprobe, symbol string }) []link.Link {
	var links []link.Link
	for _, p := range pairs {
		if prog := coll.Programs[p.uprobe]; prog != nil {
			l, err := exe.Uprobe(p.symbol, prog, nil)
			if err == nil {
				links = append(links, l)
				logger.Debug("Attached uprobe", zap.String("prog", p.uprobe), zap.String("lib", libPath))
			} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", p.symbol)) {
				logger.Info("Uprobe unavailable", zap.String("prog", p.uprobe), zap.Error(err))
			}
		}
		if prog := coll.Programs[p.uretprobe]; prog != nil {
			l, err := exe.Uretprobe(p.symbol, prog, nil)
			if err == nil {
				links = append(links, l)
			} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", p.symbol)) {
				logger.Info("Uretprobe unavailable", zap.String("prog", p.uretprobe), zap.Error(err))
			}
		}
	}
	return links
}

// AttachRedisProbes attaches hiredis uprobes for EVENT_REDIS_CMD tracing.
func AttachRedisProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachRedisProbesWithPID(coll, containerID, 0)
}

// AttachRedisProbesWithPID attaches hiredis uprobes with process-assisted library resolution.
func AttachRedisProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	var links []link.Link
	libNames := []string{"libhiredis.so.1", "libhiredis.so.0.14", "libhiredis.so"}
	paths := findDBLibsWithPID(containerID, pid, libNames)

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			continue
		}
		pairs := []struct{ uprobe, uretprobe, symbol string }{
			{"uprobe_redisCommand", "uretprobe_redisCommand", "redisCommand"},
			{"uprobe_redisCommandArgv", "uretprobe_redisCommandArgv", "redisCommandArgv"},
		}
		l := attachUprobeSymbols(exe, coll, path, pairs)
		if len(l) > 0 {
			links = append(links, l...)
			logger.Debug("Redis probes attached", zap.String("lib", path))
		}
	}
	if len(links) == 0 {
		logger.Debug("Redis probes unavailable (libhiredis not found)", zap.String("containerID", containerID))
	}
	return links
}

// AttachMemcachedProbes attaches libmemcached uprobes for EVENT_MEMCACHED_CMD tracing.
func AttachMemcachedProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachMemcachedProbesWithPID(coll, containerID, 0)
}

// AttachMemcachedProbesWithPID attaches libmemcached uprobes with process-assisted library resolution.
func AttachMemcachedProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	var links []link.Link
	libNames := []string{"libmemcached.so.11", "libmemcached.so.10", "libmemcached.so"}
	paths := findDBLibsWithPID(containerID, pid, libNames)

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			continue
		}
		pairs := []struct{ uprobe, uretprobe, symbol string }{
			{"uprobe_memcached_get", "uretprobe_memcached_get", "memcached_get"},
			{"uprobe_memcached_set", "uretprobe_memcached_set", "memcached_set"},
			{"uprobe_memcached_delete", "uretprobe_memcached_delete", "memcached_delete"},
		}
		l := attachUprobeSymbols(exe, coll, path, pairs)
		if len(l) > 0 {
			links = append(links, l...)
			logger.Debug("Memcached probes attached", zap.String("lib", path))
		}
	}
	if len(links) == 0 {
		logger.Debug("Memcached probes unavailable (libmemcached not found)", zap.String("containerID", containerID))
	}
	return links
}

// AttachKafkaProbes attaches librdkafka uprobes for Kafka produce/consume tracing.
func AttachKafkaProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachKafkaProbesWithPID(coll, containerID, 0)
}

// AttachKafkaProbesWithPID attaches librdkafka uprobes with process-assisted library resolution.
func AttachKafkaProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32) []link.Link {
	var links []link.Link
	libNames := []string{"librdkafka.so.1", "librdkafka.so"}
	paths := findDBLibsWithPID(containerID, pid, libNames)

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			continue
		}
		pairs := []struct{ uprobe, uretprobe, symbol string }{
			{"uprobe_rd_kafka_topic_new", "uretprobe_rd_kafka_topic_new", "rd_kafka_topic_new"},
			{"uprobe_rd_kafka_produce", "uretprobe_rd_kafka_produce", "rd_kafka_produce"},
			{"uprobe_rd_kafka_consumer_poll", "uretprobe_rd_kafka_consumer_poll", "rd_kafka_consumer_poll"},
		}
		l := attachUprobeSymbols(exe, coll, path, pairs)
		if len(l) > 0 {
			links = append(links, l...)
			logger.Debug("Kafka probes attached", zap.String("lib", path))
		}
	}
	if len(links) == 0 {
		logger.Debug("Kafka probes unavailable (librdkafka not found)", zap.String("containerID", containerID))
	}
	return links
}

// AttachFastCGIProbes attaches kprobes on unix_stream_sendmsg/recvmsg for
// FastCGI / PHP-FPM request lifecycle tracing (BTF-only; no-ops without BTF).
func AttachFastCGIProbes(coll *ebpf.Collection) []link.Link {
	var links []link.Link
	kprobeMap := map[string]struct {
		sym     string
		retprobe bool
	}{
		"kprobe_unix_stream_recvmsg":    {"unix_stream_recvmsg", false},
		"kretprobe_unix_stream_recvmsg": {"unix_stream_recvmsg", true},
		"kprobe_unix_stream_sendmsg":    {"unix_stream_sendmsg", false},
	}

	for progName, kp := range kprobeMap {
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}
		var l link.Link
		var err error
		if kp.retprobe {
			l, err = link.Kretprobe(kp.sym, prog, nil)
		} else {
			l, err = link.Kprobe(kp.sym, prog, nil)
		}
		if err == nil {
			links = append(links, l)
			logger.Debug("FastCGI probe attached", zap.String("prog", progName))
		} else {
			logger.Debug("FastCGI probe unavailable", zap.String("prog", progName), zap.Error(err))
		}
	}
	return links
}

// AttachGRPCProbes attaches the second kprobe on tcp_sendmsg for gRPC
// HTTP/2 HEADERS frame inspection (BTF-only; no-op without BTF).
func AttachGRPCProbes(coll *ebpf.Collection) []link.Link {
	var links []link.Link
	prog := coll.Programs["kprobe_grpc_tcp_sendmsg"]
	if prog == nil {
		return links
	}
	l, err := link.Kprobe("tcp_sendmsg", prog, nil)
	if err == nil {
		links = append(links, l)
		logger.Debug("gRPC HTTP/2 inspection probe attached")
	} else {
		logger.Debug("gRPC HTTP/2 inspection probe unavailable", zap.Error(err))
	}
	return links
}
