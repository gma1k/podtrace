//go:build embed_bpf

package podtrace

import _ "embed"

//go:embed bpf/podtrace.bpf.o
var EmbeddedPodtraceBPFObj []byte