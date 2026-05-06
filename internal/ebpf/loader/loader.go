package loader

import (
	"bytes"

	"github.com/cilium/ebpf"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/embedded"
)

func LoadPodtrace() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(config.BPFObjectPath)
	if err != nil {
		spec, err = ebpf.LoadCollectionSpec("../" + config.BPFObjectPath)
		if err != nil {
			if config.BPFObjectPath == config.DefaultBPFObjectPath() && len(embedded.EmbeddedPodtraceBPFObj) > 0 {
				if embeddedSpec, embeddedErr := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embedded.EmbeddedPodtraceBPFObj)); embeddedErr == nil {
					return embeddedSpec, nil
				}
			}
			return nil, NewLoadError(config.BPFObjectPath, err)
		}
	}

	return spec, nil
}
