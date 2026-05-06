//go:build embed_bpf && ppc64le

package embedded

import _ "embed"

//go:embed podtrace.ppc64le.bpf.o
var EmbeddedPodtraceBPFObj []byte
