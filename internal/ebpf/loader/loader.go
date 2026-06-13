package loader

import (
	"bytes"

	"github.com/cilium/ebpf"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/embedded"
)

func LoadPodtrace() (*ebpf.CollectionSpec, error) {
	spec, primaryErr := ebpf.LoadCollectionSpec(config.BPFObjectPath)
	if primaryErr != nil {
		if retrySpec, retryErr := ebpf.LoadCollectionSpec("../" + config.BPFObjectPath); retryErr == nil {
			return retrySpec, nil
		}
		if config.BPFObjectPath == config.DefaultBPFObjectPath() && len(embedded.EmbeddedPodtraceBPFObj) > 0 {
			if embeddedSpec, embeddedErr := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embedded.EmbeddedPodtraceBPFObj)); embeddedErr == nil {
				return embeddedSpec, nil
			}
		}
		return nil, NewLoadError(config.BPFObjectPath, primaryErr)
	}

	return spec, nil
}
