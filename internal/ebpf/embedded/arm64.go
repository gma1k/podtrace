//go:build embed_bpf && arm64

package embedded

import _ "embed"

//go:embed podtrace.arm64.bpf.o
var EmbeddedPodtraceBPFObj []byte
