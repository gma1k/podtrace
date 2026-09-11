package probes

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var bpfProgramName = regexp.MustCompile(`(?m)^int\s+([A-Za-z0-9_]+)\s*\(`)

func programsInBPFSource(t *testing.T) map[string]string {
	t.Helper()

	root := filepath.Join("..", "..", "..", "bpf")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	found := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".c") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range bpfProgramName.FindAllStringSubmatch(string(body), -1) {
			found[m[1]] = e.Name()
		}
	}
	if len(found) == 0 {
		t.Fatalf("no BPF programs found under %s; the extraction is broken, not the map", root)
	}
	return found
}

func TestEveryMappedProgramExists(t *testing.T) {
	real := programsInBPFSource(t)

	var missing []string
	for name := range probeGroupMap {
		if _, ok := real[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("probeGroupMap names %d program(s) that no BPF source defines: %v\n\n"+
			"A phantom name is not a harmless typo. Programs absent from probeGroupMap "+
			"default to GroupNetwork, so the real programs it was meant to cover get "+
			"classified under a group nobody enables for them — while the attach path "+
			"keys on the intended group. The two disagree, no attach failure is "+
			"recorded, and the affected metrics are silently always empty.",
			len(missing), missing)
	}
}

func TestEveryPoolProgramIsMappedToThePoolGroup(t *testing.T) {
	real := programsInBPFSource(t)

	poolSources := map[string]bool{"database.c": true, "goacquire.c": true}

	for name, file := range real {
		if !poolSources[file] {
			continue
		}
		group, mapped := probeGroupMap[name]
		if !mapped {
			t.Errorf("%s (%s) is absent from probeGroupMap, so it defaults to %q "+
				"while its siblings are %q", name, file, GroupNetwork, GroupPool)
			continue
		}
		if group != GroupPool {
			t.Errorf("%s (%s) maps to %q, want %q; a split group means the "+
				"family half-populates", name, file, group, GroupPool)
		}
	}
}

func TestGroupForProbeAgreesWithTheMap(t *testing.T) {
	for name, want := range probeGroupMap {
		if got := GroupForProbe(name); got != want {
			t.Errorf("GroupForProbe(%q) = %q, map says %q", name, got, want)
		}
	}
	if got := GroupForProbe("kprobe_definitely_not_a_real_program"); got != GroupNetwork {
		t.Errorf("unmapped program resolved to %q, want the documented %q default",
			got, GroupNetwork)
	}
}

func TestPostgresAcquireSymbolsCoverTheSynchronousAPI(t *testing.T) {
	var postgres *dbProbeConfig
	for i, cfg := range databaseProbeConfigs() {
		if cfg.name == "postgresql" {
			postgres = &databaseProbeConfigs()[i]
			break
		}
	}
	if postgres == nil {
		t.Fatal("no postgresql probe config")
	}

	have := map[string]bool{}
	for _, s := range postgres.acquireSymbols {
		have[s] = true
	}

	for _, required := range []string{"PQconnectdb", "PQconnectdbParams"} {
		if !have[required] {
			t.Errorf("acquire symbols %v omit %q.\n\nThat is the synchronous connection API, "+
				"which is what nearly every client uses — psql and pgbench included. A probe "+
				"on the asynchronous entry point alone attaches cleanly and never fires.",
				postgres.acquireSymbols, required)
		}
	}

	if have["PQconnectStartParams"] {
		t.Error("PQconnectStartParams is hooked alongside the public entry points; " +
			"they call it internally, so every connection would be counted twice")
	}
}
