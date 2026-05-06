//go:build embed_bpf && s390x

package embedded

import _ "embed"

//go:embed podtrace.s390x.bpf.o
var EmbeddedPodtraceBPFObj []byte
