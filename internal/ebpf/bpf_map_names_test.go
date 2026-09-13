package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var goMapReference = regexp.MustCompile(`Maps\["([a-z0-9_]+)"\]`)

func moduleRoot(t *testing.T) string {
	t.Helper()
	return filepath.Dir(locateBPFDir(t))
}

func declaredBPFMaps(t *testing.T) map[string]struct{} {
	t.Helper()

	bpfDir := locateBPFDir(t)
	entries, err := os.ReadDir(bpfDir)
	if err != nil {
		t.Fatalf("read bpf dir: %v", err)
	}

	declaration := regexp.MustCompile(`\}\s*([a-z0-9_]+)\s*SEC\("\.maps"\)`)
	declared := map[string]struct{}{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".h") && !strings.HasSuffix(name, ".c") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(bpfDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range declaration.FindAllStringSubmatch(string(src), -1) {
			declared[m[1]] = struct{}{}
		}
	}
	if len(declared) == 0 {
		t.Fatal("no BPF maps found in bpf/; the declaration pattern stopped matching")
	}
	return declared
}

func TestEveryMapNameUsedFromGoIsDeclaredInBPF(t *testing.T) {
	declared := declaredBPFMaps(t)
	root := moduleRoot(t)

	used := map[string][]string{}
	for _, dir := range []string{"internal", "cmd", "pkg"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range goMapReference.FindAllStringSubmatch(string(src), -1) {
				rel, _ := filepath.Rel(root, path)
				used[m[1]] = append(used[m[1]], rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	if len(used) == 0 {
		t.Fatal("no coll.Maps[\"name\"] references found; the reference pattern stopped matching")
	}

	for name, files := range used {
		if _, ok := declared[name]; !ok {
			t.Errorf("Go looks up BPF map %q (%s) but no bpf/ source declares it.\n\n"+
				"A missing map is not an error at runtime: the lookup returns nil and "+
				"the caller skips its work, so renaming a map on one side only turns the "+
				"feature off in silence.", name, strings.Join(files, ", "))
		}
	}
}
