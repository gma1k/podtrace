//go:build embed_bpf && riscv64

package embedded

import _ "embed"

//go:embed podtrace.riscv64.bpf.o
var EmbeddedPodtraceBPFObj []byte
