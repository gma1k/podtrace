package tracer

import (
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// compatSuffix marks a program that does the same job as the program named
// without it, minus a capability older kernels refuse that program type:
// task helpers in cgroup_skb, kfuncs in tracepoints. It is loaded only when
// the kernel rejects the preferred program.
const compatSuffix = "__compat"

var failedProgramName = regexp.MustCompile(`^program (\w+): `)

// splitCompatPrograms removes every compat variant from spec and returns
// them keyed by the program they stand in for.
func splitCompatPrograms(spec *ebpf.CollectionSpec) map[string]*ebpf.ProgramSpec {
	compat := map[string]*ebpf.ProgramSpec{}
	for name, prog := range spec.Programs {
		base, ok := strings.CutSuffix(name, compatSuffix)
		if !ok {
			continue
		}
		delete(spec.Programs, name)
		if _, preferred := spec.Programs[base]; preferred {
			compat[base] = prog
		}
	}
	return compat
}

// failedProgram returns the program a collection load error names, or "".
func failedProgram(err error) string {
	if err == nil {
		return ""
	}
	m := failedProgramName.FindStringSubmatch(err.Error())
	if m == nil {
		return ""
	}
	return m[1]
}

type collectionCreator func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error)

// withCompatFallback loads spec with create. When the kernel rejects a
// program that has a compat variant, the variant takes its place under the
// same name and the load is retried.
func withCompatFallback(create collectionCreator) collectionCreator {
	var compat map[string]*ebpf.ProgramSpec
	return func(spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions) (*ebpf.Collection, error) {
		if compat == nil {
			compat = splitCompatPrograms(spec)
		}
		for {
			coll, err := create(spec, opts)
			if err == nil {
				return coll, nil
			}
			name := failedProgram(err)
			alt, ok := compat[name]
			if !ok {
				return nil, err
			}
			delete(compat, name)
			replacement := alt.Copy()
			replacement.Name = spec.Programs[name].Name
			spec.Programs[name] = replacement
			reason, _, _ := strings.Cut(err.Error(), "\n")
			logger.Warn("Kernel rejected a program; loading its variant without the newer kernel feature",
				zap.String("program", name), zap.String("reason", reason))
		}
	}
}
