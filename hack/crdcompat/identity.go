package main

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
)

// Divergence is one field on which two served versions of a CRD disagree.
type Divergence struct {
	CRD      string
	VersionA string
	VersionB string
	Path     string
	Detail   string
}

func (d Divergence) String() string {
	if d.Detail == "" {
		return fmt.Sprintf("%s: %s and %s disagree on %s", d.CRD, d.VersionA, d.VersionB, d.Path)
	}
	return fmt.Sprintf("%s: %s and %s disagree on %s (%s)", d.CRD, d.VersionA, d.VersionB, d.Path, d.Detail)
}

func CheckIdentity(manifest []byte) ([]Divergence, error) {
	parsed, err := parse(manifest)
	if err != nil {
		return nil, err
	}

	served := servedSchemas(parsed)
	if len(served) < 2 {
		return nil, nil
	}

	names := make([]string, 0, len(served))
	for name := range served {
		names = append(names, name)
	}
	sort.Strings(names)

	reference := names[0]
	var out []Divergence
	for _, other := range names[1:] {
		out = append(out, compareForIdentity(parsed.Metadata.Name, reference, other, served[reference], served[other])...)
	}
	return out, nil
}

func compareForIdentity(crdName, versionA, versionB string, a, b map[string]field) []Divergence {
	paths := map[string]struct{}{}
	for path := range a {
		paths[path] = struct{}{}
	}
	for path := range b {
		paths[path] = struct{}{}
	}

	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)

	var out []Divergence
	for _, path := range ordered {
		fieldA, inA := a[path]
		fieldB, inB := b[path]
		switch {
		case inA && !inB:
			out = append(out, Divergence{crdName, versionA, versionB, path,
				fmt.Sprintf("present in %s, missing from %s", versionA, versionB)})
		case !inA && inB:
			out = append(out, Divergence{crdName, versionA, versionB, path,
				fmt.Sprintf("present in %s, missing from %s", versionB, versionA)})
		case fieldA.openAPIType != fieldB.openAPIType:
			out = append(out, Divergence{crdName, versionA, versionB, path,
				fmt.Sprintf("%s in %s, %s in %s", fieldA.openAPIType, versionA, fieldB.openAPIType, versionB)})
		default:
			if differ := fieldDifferences(fieldA, fieldB); len(differ) > 0 {
				out = append(out, Divergence{crdName, versionA, versionB, path,
					"different " + strings.Join(differ, ", ")})
			}
		}
	}
	return out
}

// fieldDifferences names every aspect of a field's schema on which two
// served versions disagree. Identity means an object round-trips between
// them unchanged and is accepted by both, so validation, nullability,
// pruning and merge semantics must all match, not only the type.
func fieldDifferences(a, b field) []string {
	var out []string
	add := func(name string, equal bool) {
		if !equal {
			out = append(out, name)
		}
	}
	add("int-or-string", a.intOrString == b.intOrString)
	add("enum", sameSet(a.enum, b.enum) && (a.enum == nil) == (b.enum == nil))
	add("pattern", a.pattern == b.pattern)
	add("bounds", maps.Equal(a.bounds, b.bounds))
	add("exclusiveMinimum", a.exclusiveMinimum == b.exclusiveMinimum)
	add("exclusiveMaximum", a.exclusiveMaximum == b.exclusiveMaximum)
	add("required", sameSet(a.required, b.required))
	add("defaults", maps.Equal(a.defaulted, b.defaulted))
	add("validation rules", sameSet(a.rules, b.rules))
	add("nullable", a.nullable == b.nullable)
	add("preserve-unknown-fields", a.preserveUnknown == b.preserveUnknown)
	add("format", a.format == b.format)
	add("list type", orDefault(a.listType, "atomic") == orDefault(b.listType, "atomic") &&
		slices.Equal(a.listMapKeys, b.listMapKeys))
	add("map type", orDefault(a.mapType, "granular") == orDefault(b.mapType, "granular"))
	add("composition", maps.Equal(a.composition, b.composition))
	return out
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func runIdentity(dir string) ([]Divergence, int, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = root.Close() }()

	names, err := manifestNames(root)
	if err != nil {
		return nil, 0, fmt.Errorf("listing %s: %w", dir, err)
	}

	var all []Divergence
	multiVersion := 0
	for _, name := range names {
		body, err := root.ReadFile(name)
		if err != nil {
			return nil, 0, err
		}
		parsed, err := parse(body)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", name, err)
		}
		if len(servedSchemas(parsed)) > 1 {
			multiVersion++
		}
		divergences, err := CheckIdentity(body)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", name, err)
		}
		all = append(all, divergences...)
	}
	return all, multiVersion, nil
}
