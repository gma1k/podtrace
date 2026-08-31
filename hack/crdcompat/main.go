package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

func main() {
	base := flag.String("base", "", "directory holding the previous revision of the CRD manifests")
	head := flag.String("head", "", "directory holding the new revision of the CRD manifests")
	identity := flag.String("identity", "", "directory of CRD manifests to check for served-version schema identity")
	flag.Parse()

	if *identity != "" {
		runIdentityMode(*identity)
		return
	}

	if *base == "" || *head == "" {
		fmt.Fprintln(os.Stderr, "usage: crdcompat -base <dir> -head <dir>")
		fmt.Fprintln(os.Stderr, "       crdcompat -identity <dir>")
		os.Exit(2)
	}

	changes, err := run(*base, *head)
	if err != nil {
		fmt.Fprintf(os.Stderr, "crdcompat: %v\n", err)
		os.Exit(2)
	}

	if len(changes) == 0 {
		fmt.Println("No breaking CRD schema changes.")
		return
	}

	fmt.Print(Report(changes))
	os.Exit(1)
}

// run compares every manifest in baseDir against its namesake in headDir.
func run(baseDir, headDir string) ([]Change, error) {
	baseRoot, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = baseRoot.Close() }()

	headRoot, err := os.OpenRoot(headDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = headRoot.Close() }()

	baseNames, err := manifestNames(baseRoot)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", baseDir, err)
	}
	headNames, err := manifestNames(headRoot)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", headDir, err)
	}

	var all []Change
	for _, name := range baseNames {
		if !headNames.has(name) {
			all = append(all, Change{
				CRD:    name,
				Kind:   VersionRemoved,
				Path:   name,
				Detail: "manifest no longer generated",
			})
			continue
		}

		oldYAML, err := baseRoot.ReadFile(name)
		if err != nil {
			return nil, err
		}
		newYAML, err := headRoot.ReadFile(name)
		if err != nil {
			return nil, err
		}

		changes, err := Compare(oldYAML, newYAML)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		all = append(all, changes...)
	}
	return all, nil
}

// nameSet is the set of manifest names found in one directory.
type nameSet []string

func (s nameSet) has(name string) bool {
	for _, candidate := range s {
		if candidate == name {
			return true
		}
	}
	return false
}

// manifestNames lists the YAML files directly inside root, sorted, so that a
// report is ordered the same way on every run.
func manifestNames(root *os.Root) (nameSet, error) {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}

	names := make(nameSet, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// runIdentityMode enforces the graduation contract: every served version of a
// CRD must describe the same schema, because `conversion.strategy.
func runIdentityMode(dir string) {
	divergences, multiVersion, err := runIdentity(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "crdcompat: %v\n", err)
		os.Exit(2)
	}

	if len(divergences) == 0 {
		if multiVersion == 0 {
			fmt.Println("No CRD serves more than one version; schema identity is trivially satisfied.")
			return
		}
		fmt.Printf("Served versions are schema-identical in %d multi-version CRD(s).\n", multiVersion)
		return
	}

	for _, d := range divergences {
		fmt.Println(d)
	}
	os.Exit(1)
}
