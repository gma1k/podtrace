//go:build embed_bpf && amd64

package embedded

import _ "embed"

//go:embed podtrace.amd64.bpf.o
var EmbeddedPodtraceBPFObj []byte
